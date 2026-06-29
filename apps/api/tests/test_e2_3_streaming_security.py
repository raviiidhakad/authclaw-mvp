import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.engine.audit import AuditEngine
from app.core.engine.streaming import StreamingEngine, StreamingMode


class FakeScanResult:
    def __init__(self, text, sanitized_text=None, detections=None):
        self.original_text = text
        self.sanitized_text = sanitized_text if sanitized_text is not None else text
        self.detections = detections or []
        self.latency_ms = 2

    @property
    def has_detections(self):
        return bool(self.detections)

    @property
    def entity_types(self):
        return list({item["entity_type"] for item in self.detections})


class FakePresidio:
    def __init__(self, scan_result=None, healthy=True, exc=None):
        self.scan_result = scan_result
        self.healthy = healthy
        self.exc = exc

    def is_healthy(self):
        return self.healthy

    async def scan(self, text):
        if self.exc:
            raise self.exc
        return self.scan_result or FakeScanResult(text)


class FakeDbContext:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *_args):
        return None


class FakeStreamContext:
    status_code = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeClientContext:
    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, *_args, **_kwargs):
        return FakeStreamContext()


class FakeProducer:
    async def publish_security_event(self, _event):
        return None


def _detection(text, value, entity_type="EMAIL_ADDRESS"):
    start = text.index(value)
    return {"entity_type": entity_type, "start": start, "end": start + len(value), "score": 0.99}


def _engine():
    audit = MagicMock(spec=AuditEngine)
    audit.publish_stream_started = AsyncMock()
    audit.publish_stream_completed = AsyncMock()
    audit.publish_stream_failed = AsyncMock()
    return StreamingEngine(audit), audit


def _adapter(chunks):
    adapter = MagicMock()
    adapter.transform_request.return_value = {"messages": [], "stream": True}

    async def stream_response(_response):
        for chunk in chunks:
            yield chunk

    adapter.stream_response = stream_response
    return adapter


async def _render_with_security(monkeypatch, text, scan_result, compiled_policy):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_STREAM_SCAN", True)
    monkeypatch.setattr("app.core.detection.presidio_engine.presidio_engine", FakePresidio(scan_result))
    monkeypatch.setattr("app.core.database.AsyncSessionLocal", lambda: FakeDbContext())
    monkeypatch.setattr("app.core.policy.cache.policy_cache.get", AsyncMock(return_value=compiled_policy))
    monkeypatch.setattr("app.core.events.producer.producer", FakeProducer())

    engine, audit = _engine()
    adapter = _adapter([
        f'data: {{"choices":[{{"delta":{{"content":"{text}"}}}}]}}\n\n'.encode("utf-8"),
        b"data: [DONE]\n\n",
    ])
    with patch("httpx.AsyncClient", FakeClientContext):
        response = await engine.stream_response(
            tenant_id=uuid.uuid4(),
            api_key_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [], "stream": True},
            provider_name="test",
            adapter=adapter,
            streaming_mode=StreamingMode.BUFFERED,
        )
        rendered = "".join([chunk async for chunk in response.body_iterator])
    return rendered, audit


@pytest.mark.asyncio
async def test_streaming_policy_allow_releases_clean_text(monkeypatch):
    rendered, audit = await _render_with_security(
        monkeypatch,
        "clean response",
        FakeScanResult("clean response"),
        {"entity_actions": {}, "keyword_blocklist": [], "policy_ids": ["policy-1"]},
    )

    assert "clean response" in rendered
    audit.publish_stream_completed.assert_called_once()
    audit.publish_stream_failed.assert_not_called()


@pytest.mark.asyncio
async def test_streaming_policy_block_fails_closed(monkeypatch):
    rendered, audit = await _render_with_security(
        monkeypatch,
        "contains secret",
        FakeScanResult("contains secret"),
        {"entity_actions": {}, "keyword_blocklist": ["secret"], "policy_ids": ["policy-1"]},
    )

    assert "contains secret" not in rendered
    assert "Response blocked by AuthClaw security policy" in rendered
    assert "response_blocked" in rendered
    audit.publish_stream_failed.assert_called_once()
    audit.publish_stream_completed.assert_not_called()


@pytest.mark.asyncio
async def test_streaming_policy_redact_masks_pii(monkeypatch):
    text = "email person@example.test"
    scan = FakeScanResult(text, "email [EMAIL_ADDRESS]", [_detection(text, "person@example.test")])

    rendered, audit = await _render_with_security(
        monkeypatch,
        text,
        scan,
        {"entity_actions": {"EMAIL_ADDRESS": "MASK"}, "keyword_blocklist": [], "policy_ids": ["policy-1"]},
    )

    assert "person@example.test" not in rendered
    assert "[EMAIL_ADDRESS]" in rendered
    audit.publish_stream_completed.assert_called_once()


@pytest.mark.asyncio
async def test_streaming_hash_reuses_existing_redaction_helper(monkeypatch):
    text = "email person@example.test"
    scan = FakeScanResult(text, "email [EMAIL_ADDRESS]", [_detection(text, "person@example.test")])

    rendered, _audit = await _render_with_security(
        monkeypatch,
        text,
        scan,
        {"entity_actions": {"EMAIL_ADDRESS": "HASH"}, "keyword_blocklist": [], "policy_ids": ["policy-1"]},
    )

    assert "person@example.test" not in rendered
    assert "HASHED_EMAIL_ADDRESS" in rendered


@pytest.mark.asyncio
async def test_streaming_synthetic_reuses_existing_redaction_helper(monkeypatch):
    text = "email person@example.test"
    scan = FakeScanResult(text, "email [EMAIL_ADDRESS]", [_detection(text, "person@example.test")])

    rendered, _audit = await _render_with_security(
        monkeypatch,
        text,
        scan,
        {"entity_actions": {"EMAIL_ADDRESS": "SYNTHETIC"}, "keyword_blocklist": [], "policy_ids": ["policy-1"]},
    )

    assert "person@example.test" not in rendered
    assert "synthetic" in rendered.lower() or "example" in rendered.lower()


@pytest.mark.asyncio
async def test_streaming_reversible_tokenization_uses_token_vault(monkeypatch):
    text = "email person@example.test"
    scan = FakeScanResult(text, "email [EMAIL_ADDRESS]", [_detection(text, "person@example.test")])
    store_batch = AsyncMock()
    monkeypatch.setattr("app.core.engine.token_vault.TokenVaultService.store_batch", store_batch)

    rendered, _audit = await _render_with_security(
        monkeypatch,
        text,
        scan,
        {
            "entity_actions": {"EMAIL_ADDRESS": "MASK"},
            "reversible_entities": ["EMAIL_ADDRESS"],
            "keyword_blocklist": [],
            "policy_ids": ["policy-1"],
        },
    )

    assert "person@example.test" not in rendered
    assert "{{AUTHCLAW:TOKEN:" in rendered
    store_batch.assert_called_once()


@pytest.mark.asyncio
async def test_streaming_security_failure_fails_closed(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_STREAM_SCAN", True)
    monkeypatch.setattr("app.core.detection.presidio_engine.presidio_engine", FakePresidio(healthy=False))

    engine, audit = _engine()
    adapter = _adapter([b'data: {"choices":[{"delta":{"content":"unsafe"}}]}\n\n', b"data: [DONE]\n\n"])
    with patch("httpx.AsyncClient", FakeClientContext):
        response = await engine.stream_response(
            tenant_id=uuid.uuid4(),
            api_key_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [], "stream": True},
            provider_name="test",
            adapter=adapter,
        )
        rendered = "".join([chunk async for chunk in response.body_iterator])

    assert "unsafe" not in rendered
    assert "stream_security_scan_failed" in rendered
    audit.publish_stream_failed.assert_called_once()


@pytest.mark.asyncio
async def test_streaming_cross_chunk_pii_is_redacted_after_reassembly(monkeypatch):
    text = "email person@example.test"
    scan = FakeScanResult(text, "email [EMAIL_ADDRESS]", [_detection(text, "person@example.test")])
    monkeypatch.setattr("app.core.config.settings.FF_SECURITY_PIPELINE", True)
    monkeypatch.setattr("app.core.config.settings.FF_STREAM_SCAN", True)
    monkeypatch.setattr("app.core.detection.presidio_engine.presidio_engine", FakePresidio(scan))
    monkeypatch.setattr("app.core.database.AsyncSessionLocal", lambda: FakeDbContext())
    monkeypatch.setattr(
        "app.core.policy.cache.policy_cache.get",
        AsyncMock(return_value={"entity_actions": {"EMAIL_ADDRESS": "MASK"}, "keyword_blocklist": []}),
    )
    monkeypatch.setattr("app.core.events.producer.producer", FakeProducer())

    engine, _audit = _engine()
    adapter = _adapter([
        b'data: {"choices":[{"delta":{"content":"email per',
        b'son@example.test"}}]}\n\n',
        b"data: [DONE]\n\n",
    ])
    with patch("httpx.AsyncClient", FakeClientContext):
        response = await engine.stream_response(
            tenant_id=uuid.uuid4(),
            api_key_id=uuid.uuid4(),
            provider_id=uuid.uuid4(),
            url="https://provider.example/chat/completions",
            headers={},
            payload={"messages": [], "stream": True},
            provider_name="test",
            adapter=adapter,
        )
        rendered = "".join([chunk async for chunk in response.body_iterator])

    assert "person@example.test" not in rendered
    assert "[EMAIL_ADDRESS]" in rendered
