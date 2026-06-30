import json
import uuid
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.engine.audit import AuditEngine
from app.core.engine.gateway import GatewayService
from app.core.engine.streaming import StreamingEngine, StreamingMode
from app.models.audit import AuditLog
from app.models.gateway import GatewayRequest, GatewayResponse
from app.models.gateway_route import RedactionStrategy
from app.models.policy import PolicyAction, RuleType
from app.models.provider import ProviderType


class FakeScalarResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._all_items = all_items if all_items is not None else ([] if first is None else [first])

    def first(self):
        return self._first

    def all(self):
        return self._all_items


class FakeResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._scalars = FakeScalarResult(first=first, all_items=all_items)

    def scalars(self):
        return self._scalars

    def fetchone(self):
        return self._first

    def scalar(self):
        return self._first


class FakeDb:
    def __init__(self, *results, allow_empty_execute=False):
        self.results = list(results)
        self.added = []
        self.allow_empty_execute = allow_empty_execute

    async def execute(self, _stmt, *_args, **_kwargs):
        if self.allow_empty_execute:
            params = getattr(_stmt.compile(), "params", {})
            if {"id", "tenant_id", "previous_hash", "hash", "metadata"}.issubset(params):
                self.added.append(
                    AuditLog(
                        id=params["id"],
                        tenant_id=params["tenant_id"],
                        user_id=params.get("user_id"),
                        event_type=params.get("event_type"),
                        action=params.get("action"),
                        resource=params.get("resource"),
                        resource_id=params.get("resource_id"),
                        metadata_=params.get("metadata"),
                        ip_address=params.get("ip_address"),
                        user_agent=params.get("user_agent"),
                        created_at=params.get("created_at"),
                        previous_hash=params.get("previous_hash"),
                        hash=params.get("hash"),
                    )
                )
                return FakeResult()
        if not self.results:
            if self.allow_empty_execute:
                return FakeResult()
            raise AssertionError("Unexpected DB query in gateway phase 5 test")
        return self.results.pop(0)

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def flush(self):
        return None


class FakeStreamContext:
    def __init__(self, status_code=200):
        self.status_code = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeAsyncClient:
    calls = []
    status_code = 200

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, url_method, url, headers, json):
        self.__class__.calls.append({"method": url_method, "url": url, "headers": headers, "json": json})
        return FakeStreamContext(self.__class__.status_code)


def _provider(provider_type=ProviderType.groq):
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=f"{provider_type.value} api",
        type=provider_type,
        config={"base_url": "https://api.groq.com/openai/v1"},
        is_active=True,
    )


def _route(provider_id, policy_id=None, redaction=RedactionStrategy.mask):
    config = {"model": "llama3-8b-8192"}
    if policy_id:
        config["policy_id"] = str(policy_id)
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="groq",
        provider_id=provider_id,
        is_default=False,
        is_active=True,
        redaction=redaction,
        config=config,
        created_at=datetime.utcnow(),
    )


def _policy(tenant_id):
    policy_id = uuid.uuid4()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        policy_id=policy_id,
        rule_type=RuleType.content_filter,
        conditions={"keywords": ["token="]},
        action=PolicyAction.block,
        message="Credential marker blocked.",
        is_active=True,
    )
    return SimpleNamespace(
        id=policy_id,
        tenant_id=tenant_id,
        name="Credential leakage block",
        description="Blocks demo credential markers.",
        is_active=True,
        priority=10,
        rules=[rule],
    )


def _payload(message="Explain machine learning.", stream=True, streaming_mode="buffered"):
    payload = {
        "model": "client-selected-model",
        "route": "groq",
        "messages": [{"role": "user", "content": message}],
        "stream": stream,
    }
    if streaming_mode:
        payload["streaming_mode"] = streaming_mode
    return payload


def _streaming_adapter(chunks):
    adapter = MagicMock()
    adapter.transform_request.side_effect = lambda payload: payload

    async def stream_response(_resp):
        for chunk in chunks:
            yield chunk

    adapter.stream_response = stream_response
    return adapter


@pytest.mark.asyncio
async def test_streaming_request_redacts_prompt_before_provider_egress():
    FakeAsyncClient.calls = []
    FakeAsyncClient.status_code = 200
    adapter = _streaming_adapter([b'data: {"choices":[{"delta":{"content":"ok"}}]}', b"data: [DONE]"])
    audit = MagicMock()
    audit.publish_stream_started = AsyncMock()
    audit.publish_stream_completed = AsyncMock()
    audit.publish_stream_failed = AsyncMock()
    engine = StreamingEngine(audit)

    with patch("httpx.AsyncClient", FakeAsyncClient):
        response = await engine.stream_response(
            tenant_id=uuid.uuid4(),
            api_key_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            url="https://provider.example/chat/completions",
            headers={},
            payload=_payload("Email person@example.test should be protected."),
            provider_name="groq",
            adapter=adapter,
            streaming_mode=StreamingMode.BUFFERED,
        )
        chunks = [chunk async for chunk in response.body_iterator]

    egress_text = FakeAsyncClient.calls[0]["json"]["messages"][0]["content"]
    assert "person@example.test" not in egress_text
    assert "[redacted]" in egress_text
    assert "ok" in "".join(chunks)


@pytest.mark.asyncio
async def test_streaming_response_sensitive_chunk_is_redacted_before_release():
    FakeAsyncClient.calls = []
    FakeAsyncClient.status_code = 200
    adapter = _streaming_adapter([
        b'data: {"choices":[{"delta":{"content":"Contact person@example.test"}}]}',
        b"data: [DONE]",
    ])
    audit = MagicMock()
    audit.publish_stream_started = AsyncMock()
    audit.publish_stream_completed = AsyncMock()
    audit.publish_stream_failed = AsyncMock()
    engine = StreamingEngine(audit)

    with patch("httpx.AsyncClient", FakeAsyncClient):
        response = await engine.stream_response(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "https://provider.example", {}, _payload(), "groq", adapter)
        rendered = "".join([chunk async for chunk in response.body_iterator])

    assert "person@example.test" not in rendered
    assert "[redacted]" in rendered
    audit.publish_stream_completed.assert_called_once()


@pytest.mark.asyncio
async def test_streaming_scanner_failure_does_not_leak_raw_chunk(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.status_code = 200
    adapter = _streaming_adapter([
        b'data: {"choices":[{"delta":{"content":"secret token=demo-token"}}]}',
        b"data: [DONE]",
    ])
    audit = MagicMock()
    audit.publish_stream_started = AsyncMock()
    audit.publish_stream_completed = AsyncMock()
    audit.publish_stream_failed = AsyncMock()
    engine = StreamingEngine(audit)

    async def fail_scan(_text):
        raise RuntimeError("scanner exploded with token=demo-token")

    monkeypatch.setattr(engine, "_sanitize_stream_text", fail_scan)

    with patch("httpx.AsyncClient", FakeAsyncClient):
        response = await engine.stream_response(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "https://provider.example", {}, _payload(), "groq", adapter)
        rendered = "".join([chunk async for chunk in response.body_iterator])

    assert "demo-token" not in rendered
    assert "secret token" not in rendered
    assert "stream_security_scan_failed" in rendered
    audit.publish_stream_failed.assert_called_once()
    audit.publish_stream_completed.assert_not_called()


@pytest.mark.asyncio
async def test_provider_stream_error_is_sanitized():
    FakeAsyncClient.calls = []
    FakeAsyncClient.status_code = 401
    adapter = _streaming_adapter([])
    audit = MagicMock()
    audit.publish_stream_started = AsyncMock()
    audit.publish_stream_completed = AsyncMock()
    audit.publish_stream_failed = AsyncMock()
    engine = StreamingEngine(audit)

    with patch("httpx.AsyncClient", FakeAsyncClient):
        response = await engine.stream_response(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), "https://provider.example", {}, _payload(), "groq", adapter)
        rendered = "".join([chunk async for chunk in response.body_iterator])

    assert "gsk_" not in rendered
    assert "provider streaming failed" in rendered.lower()
    audit.publish_stream_failed.assert_called_once()
    audit.publish_stream_started.assert_not_called()


@pytest.mark.asyncio
async def test_gateway_passthrough_streaming_remains_blocked_before_provider(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    provider = _provider()
    route = _route(provider.id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(all_items=[])))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock()

    result = await service.process_chat_request(uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), _payload(streaming_mode="passthrough"))

    assert result["status_code"] == 400
    assert result["data"]["error"]["code"] == "passthrough_streaming_disabled"
    service.ai_client.chat_completion.assert_not_called()


@pytest.mark.asyncio
async def test_route_attached_policy_blocks_stream_before_provider_call(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", False)
    tenant_id = uuid.uuid4()
    provider = _provider()
    policy = _policy(tenant_id)
    route = _route(provider.id, policy_id=policy.id)
    service = GatewayService(FakeDb(FakeResult(route), FakeResult(provider), FakeResult(policy)))
    service.audit_engine.log_request = AsyncMock()
    service.ai_client.chat_completion = AsyncMock()

    result = await service.process_chat_request(tenant_id, uuid.uuid4(), uuid.uuid4(), _payload("token=demo-secret", stream=True))

    assert result["status_code"] == 403
    assert result["data"]["error"]["type"] == "policy_violation"
    service.ai_client.chat_completion.assert_not_called()


@pytest.mark.asyncio
async def test_audit_storage_is_sanitized_only_by_default(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION", False)
    db = FakeDb(allow_empty_execute=True)
    audit = AuditEngine(db)

    await audit.log_request(
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        provider_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
        model="llama3-8b-8192",
        original_payload={"messages": [{"role": "user", "content": "email person@example.test token=demo-secret"}]},
        modified_payload={"messages": [{"role": "user", "content": "email [redacted] [redacted]"}]},
        response_payload={"choices": [{"message": {"content": "call +1 202-555-0100 token=demo-secret"}}]},
        tokens_prompt=1,
        tokens_completion=1,
        latency_ms=12,
        status_code=200,
    )

    request = next(item for item in db.added if isinstance(item, GatewayRequest))
    response = next(item for item in db.added if isinstance(item, GatewayResponse))
    audit_log = next(item for item in db.added if isinstance(item, AuditLog))
    rendered = f"{request.prompt_original} {request.prompt_redacted} {response.response_original} {response.response_redacted} {audit_log.metadata_}"

    assert "person@example.test" not in rendered
    assert "demo-secret" not in rendered
    assert "+1 202-555-0100" not in rendered
    assert audit_log.metadata_["raw_gateway_audit_retention"] is False
    assert audit_log.metadata_["stored_prompt"] == "sanitized_preview"
    assert audit_log.metadata_["prompt_original_hash"]
    assert audit_log.metadata_["response_original_hash"]


@pytest.mark.asyncio
async def test_raw_retention_flag_is_explicit_and_api_schemas_still_sanitize(monkeypatch):
    from app.schemas.gateway import GatewayRequestDetail, GatewayResponseSchema

    monkeypatch.setattr("app.core.config.settings.ENABLE_RAW_GATEWAY_AUDIT_RETENTION", True)
    db = FakeDb(allow_empty_execute=True)
    audit = AuditEngine(db)

    await audit.log_request(
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        provider_id=uuid.uuid4(),
        api_key_id=uuid.uuid4(),
        model="llama3-8b-8192",
        original_payload={"messages": [{"role": "user", "content": "email person@example.test token=demo-secret"}]},
        modified_payload={"messages": [{"role": "user", "content": "email [redacted] [redacted]"}]},
        response_payload={"choices": [{"message": {"content": "token=demo-secret"}}]},
        tokens_prompt=1,
        tokens_completion=1,
        latency_ms=12,
        status_code=200,
    )

    request = next(item for item in db.added if isinstance(item, GatewayRequest))
    response = next(item for item in db.added if isinstance(item, GatewayResponse))
    assert "person@example.test" in request.prompt_original
    assert "demo-secret" in str(response.response_original)

    dumped_request = GatewayRequestDetail.model_validate(
        SimpleNamespace(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            model="llama3-8b-8192",
            prompt_original=request.prompt_original,
            prompt_redacted=request.prompt_redacted,
            status="completed",
            token_count_prompt=1,
            latency_ms=12,
            provider_status_code=200,
            error_message=None,
            error_type=None,
            error_code=None,
            created_at=datetime.utcnow(),
            response=None,
            violations=[],
        )
    ).model_dump()
    dumped_response = GatewayResponseSchema.model_validate(
        SimpleNamespace(
            id=uuid.uuid4(),
            request_id=uuid.uuid4(),
            response_original=response.response_original,
            response_redacted=response.response_redacted,
            pii_detections=[],
            token_count_completion=1,
            latency_ms=12,
            created_at=datetime.utcnow(),
        )
    ).model_dump()

    rendered = f"{dumped_request} {dumped_response}"
    assert "person@example.test" not in rendered
    assert "demo-secret" not in rendered
