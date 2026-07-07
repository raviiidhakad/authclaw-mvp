"""
Provider Contract Tests
========================
Tests that verify each adapter correctly transforms requests and responses.

Structure:
  - UNIT tests: offline, always run, mock HTTP
  - LIVE tests: only run when credentials are present (skip otherwise)

Live tests call real provider endpoints and validate:
  1. Synchronous chat completion returns an OpenAI-compatible response
  2. Streaming returns valid SSE chunks
"""
import json
import os
import time
import asyncio
import pytest
import httpx
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.provider import ProviderType
from app.core.providers.factory import ProviderAdapterFactory
from app.core.providers.adapters.openai import OpenAIAdapter
from app.core.providers.adapters.anthropic import AnthropicAdapter
from app.core.providers.adapters.cohere import CohereAdapter
from app.core.providers.adapters.gemini import GeminiAdapter
from app.core.providers.adapters.azure import AzureOpenAIAdapter

from tests.integration.providers.conftest import (
    requires_openai, requires_anthropic, requires_groq,
    requires_gemini, requires_cohere, requires_azure,
    FakeProvider, _encrypt_test_key,
    OPENAI_KEY, ANTHROPIC_KEY, GROQ_KEY, GEMINI_KEY, COHERE_KEY, AZURE_KEY,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STANDARD_PAYLOAD = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
    "max_tokens": 10,
}

def _openai_compat_response(body: dict) -> None:
    """Assert a body is OpenAI-compatible chat completion."""
    assert "choices" in body, f"Missing 'choices' in response: {body}"
    assert len(body["choices"]) > 0, "Empty 'choices' list"
    choice = body["choices"][0]
    msg = choice.get("message") or {}
    assert "content" in msg, f"Missing 'content' in message: {msg}"
    assert isinstance(msg["content"], str), "content must be a string"
    assert "usage" in body, f"Missing 'usage' in response: {body}"


# ===========================================================================
# ─── UNIT TESTS (always run, no credentials needed) ────────────────────────
# ===========================================================================

class TestOpenAIAdapterUnit:
    """Offline unit tests for OpenAIAdapter."""

    def test_transform_request_passthrough(self):
        adapter = OpenAIAdapter()
        payload = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
        assert adapter.transform_request(payload) == payload

    def test_transform_response_passthrough(self):
        adapter = OpenAIAdapter()
        body = {"choices": [{"message": {"content": "hello"}}], "usage": {"total_tokens": 5}}
        assert adapter.transform_response(body) == body

    def test_normalize_error_json(self):
        adapter = OpenAIAdapter()
        raw = json.dumps({"error": {"message": "invalid key", "type": "auth_error", "code": "invalid_api_key"}})
        result = adapter.normalize_error(401, raw)
        assert result["error"]["message"] == "Provider authentication failed. Update the provider credential in Settings."
        assert result["error"]["type"] == "provider_auth_error"
        assert result["error"]["code"] == "invalid_provider_credentials"

    def test_normalize_error_non_json(self):
        adapter = OpenAIAdapter()
        result = adapter.normalize_error(500, "Internal Server Error")
        assert "error" in result
        assert isinstance(result["error"]["message"], str)


class TestAnthropicAdapterUnit:
    """Offline unit tests for AnthropicAdapter."""

    def test_transform_request_system_extraction(self):
        adapter = AnthropicAdapter()
        payload = {
            "model": "claude-3-haiku-20240307",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"},
            ],
        }
        transformed = adapter.transform_request(payload)
        assert transformed["system"] == "You are helpful."
        assert len(transformed["messages"]) == 1
        assert transformed["messages"][0]["role"] == "user"

    def test_transform_request_no_system(self):
        adapter = AnthropicAdapter()
        payload = {
            "model": "claude-3-haiku-20240307",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        transformed = adapter.transform_request(payload)
        assert "system" not in transformed
        assert len(transformed["messages"]) == 1

    def test_transform_response_normalizes_to_openai(self):
        adapter = AnthropicAdapter()
        anthropic_body = {
            "id": "msg_123",
            "model": "claude-3-haiku",
            "content": [{"type": "text", "text": "Hello!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        result = adapter.transform_response(anthropic_body)
        _openai_compat_response(result)
        assert result["choices"][0]["message"]["content"] == "Hello!"
        assert result["usage"]["prompt_tokens"] == 10
        assert result["usage"]["completion_tokens"] == 5

    def test_normalize_error(self):
        adapter = AnthropicAdapter()
        raw = json.dumps({"error": {"type": "authentication_error", "message": "invalid x-api-key"}})
        result = adapter.normalize_error(401, raw)
        assert result["error"]["message"] == "Provider authentication failed. Update the provider credential in Settings."
        assert result["error"]["type"] == "provider_auth_error"


class TestCohereAdapterUnit:
    """Offline unit tests for CohereAdapter."""

    def test_transform_request_maps_messages(self):
        adapter = CohereAdapter()
        payload = {
            "model": "command-r",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "What is 2+2?"},
            ],
        }
        result = adapter.transform_request(payload)
        assert result["message"] == "What is 2+2?"
        assert len(result["chat_history"]) == 1
        assert result["chat_history"][0]["role"] == "SYSTEM"
        assert result["chat_history"][0]["message"] == "Be concise."

    def test_transform_request_multi_turn(self):
        adapter = CohereAdapter()
        payload = {
            "model": "command-r",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "user", "content": "How are you?"},
            ],
        }
        result = adapter.transform_request(payload)
        assert result["message"] == "How are you?"
        assert len(result["chat_history"]) == 2
        assert result["chat_history"][1]["role"] == "CHATBOT"

    def test_transform_response_normalizes_to_openai(self):
        adapter = CohereAdapter()
        cohere_body = {
            "generation_id": "gen_123",
            "text": "Four.",
            "meta": {"billed_units": {"input_tokens": 8, "output_tokens": 2}},
        }
        result = adapter.transform_response(cohere_body)
        _openai_compat_response(result)
        assert result["choices"][0]["message"]["content"] == "Four."

    def test_normalize_error(self):
        adapter = CohereAdapter()
        raw = json.dumps({"message": "invalid api key"})
        result = adapter.normalize_error(401, raw)
        assert result["error"]["message"] == "Provider authentication failed. Update the provider credential in Settings."
        assert result["error"]["type"] == "provider_auth_error"


class TestGeminiAdapterUnit:
    """Offline unit tests for GeminiAdapter (inherits OpenAI behavior)."""

    def test_transform_request_passthrough(self):
        adapter = GeminiAdapter()
        payload = {"model": "gemini-pro", "messages": [{"role": "user", "content": "hi"}]}
        assert adapter.transform_request(payload) == payload

    def test_transform_response_passthrough(self):
        adapter = GeminiAdapter()
        body = {"choices": [{"message": {"content": "hi"}}], "usage": {}}
        assert adapter.transform_response(body) == body


# ===========================================================================
# -- PHASE D DETERMINISTIC CONTRACT TESTS (always run, no credentials needed)
# ===========================================================================

class _LineStream:
    def __init__(self, lines):
        self._lines = lines

    async def aiter_lines(self):
        for line in self._lines:
            yield line


def _provider(provider_type, config=None):
    return SimpleNamespace(
        id="provider-id",
        tenant_id="tenant-id",
        name=f"{provider_type.value} provider",
        type=provider_type,
        config=config or {},
        is_active=True,
    )


async def _collect_stream_text(adapter, lines):
    chunks = []
    done = False
    async for raw in adapter.stream_response(_LineStream(lines)):
        text = raw.decode("utf-8").strip()
        if text == "data: [DONE]":
            done = True
            continue
        assert text.startswith("data: ")
        payload = json.loads(text[len("data: "):])
        chunks.append(payload["choices"][0]["delta"].get("content", ""))
    return "".join(chunks), done


@pytest.mark.parametrize(
    ("provider_type", "adapter", "patch_path", "config", "expected_url", "header_name"),
    [
        (ProviderType.openai, OpenAIAdapter(), "app.core.providers.adapters.openai.retrieve_provider_api_key", {}, "https://api.openai.com/v1/chat/completions", "Authorization"),
        (ProviderType.anthropic, AnthropicAdapter(), "app.core.providers.adapters.anthropic.retrieve_provider_api_key", {}, "https://api.anthropic.com/v1/messages", "x-api-key"),
        (ProviderType.cohere, CohereAdapter(), "app.core.providers.adapters.cohere.retrieve_provider_api_key", {}, "https://api.cohere.ai/v1/chat", "Authorization"),
        (
            ProviderType.azure_openai,
            AzureOpenAIAdapter(),
            "app.core.providers.adapters.azure.retrieve_provider_api_key",
            {"auth_type": "api_key", "azure_resource_name": "authclaw-eastus", "azure_deployment_id": "gpt-4o-mini", "azure_api_version": "2024-02-01"},
            "https://authclaw-eastus.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-01",
            "api-key",
        ),
    ],
)
@pytest.mark.asyncio
async def test_phase_d_provider_endpoint_and_auth_contract(monkeypatch, provider_type, adapter, patch_path, config, expected_url, header_name):
    monkeypatch.setattr(patch_path, AsyncMock(return_value="provider-secret-placeholder"))

    url, headers = await adapter.get_connection_details(_provider(provider_type, config))

    assert url == expected_url
    assert headers[header_name]
    assert "provider-secret-placeholder" in headers[header_name]
    assert "Content-Type" in headers


def test_phase_d_request_tuning_fields_are_mapped():
    payload = {
        "model": "provider-model",
        "messages": [
            {"role": "system", "content": "Be concise."},
            {"role": "user", "content": "Hello"},
        ],
        "max_tokens": 17,
        "temperature": 0.2,
        "stream": True,
    }

    assert OpenAIAdapter().transform_request(payload)["temperature"] == 0.2
    assert AzureOpenAIAdapter().transform_request(payload)["max_tokens"] == 17

    anthropic = AnthropicAdapter().transform_request(payload)
    assert anthropic["max_tokens"] == 17
    assert anthropic["temperature"] == 0.2
    assert anthropic["stream"] is True
    assert anthropic["system"] == "Be concise."

    cohere = CohereAdapter().transform_request(payload)
    assert cohere["message"] == "Hello"
    assert cohere["max_tokens"] == 17
    assert cohere["temperature"] == 0.2
    assert cohere["stream"] is True


@pytest.mark.parametrize(
    ("adapter", "lines"),
    [
        (OpenAIAdapter(), ['data: {"choices":[{"delta":{"content":"Hel"}}]}', 'data: {"choices":[{"delta":{"content":"lo"}}]}', 'data: [DONE]']),
        (AzureOpenAIAdapter(), ['data: {"choices":[{"delta":{"content":"Hel"}}]}', 'data: {"choices":[{"delta":{"content":"lo"}}]}', 'data: [DONE]']),
        (AnthropicAdapter(), ['event: content_block_delta', 'data: {"type":"content_block_delta","delta":{"text":"Hel"}}', 'data: {malformed}', 'data: {"type":"content_block_delta","delta":{"text":"lo"}}', 'data: {"type":"message_stop"}']),
        (CohereAdapter(), ['{"event_type":"text-generation","text":"Hel"}', '{malformed}', '{"event_type":"text-generation","text":"lo"}', '{"event_type":"stream-end"}']),
    ],
)
@pytest.mark.asyncio
async def test_phase_d_streaming_contract_maps_content_and_done(adapter, lines):
    text, done = await _collect_stream_text(adapter, lines)

    assert text == "Hello"
    assert done is True


@pytest.mark.parametrize(
    "adapter",
    [OpenAIAdapter(), AnthropicAdapter(), CohereAdapter(), AzureOpenAIAdapter()],
)
def test_phase_d_provider_errors_are_sanitized(adapter):
    result = adapter.normalize_error(429, '{"error":{"message":"rate limit for sk-proj-secret","type":"rate_limit_error","code":"rate_limit"},"message":"rate limit for sk-proj-secret"}')

    rendered = json.dumps(result)
    assert "sk-proj-secret" not in rendered
    assert "error" in result


class _InvalidJsonResponse:
    status_code = 200
    text = "not json"

    def json(self):
        raise ValueError("invalid json")


class _InvalidJsonClient:
    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, *_args, **_kwargs):
        return _InvalidJsonResponse()


class _TimeoutClient(_InvalidJsonClient):
    async def post(self, *_args, **_kwargs):
        raise httpx.ReadTimeout("slow provider")


class _CancelledClient(_InvalidJsonClient):
    async def post(self, *_args, **_kwargs):
        raise asyncio.CancelledError()


@pytest.mark.asyncio
async def test_phase_d_malformed_success_response_fails_closed(monkeypatch):
    from app.core.engine.gateway import AIProviderClient

    monkeypatch.setattr("app.core.providers.adapters.openai.retrieve_provider_api_key", AsyncMock(return_value="provider-secret-placeholder"))
    monkeypatch.setattr("httpx.AsyncClient", _InvalidJsonClient)

    response = await AIProviderClient().chat_completion(_provider(ProviderType.openai), STANDARD_PAYLOAD)

    assert response.status_code == 502
    assert response.body["error"]["code"] == "invalid_json"


@pytest.mark.asyncio
async def test_phase_d_timeout_maps_to_gateway_timeout(monkeypatch):
    from app.core.engine.gateway import AIProviderClient

    monkeypatch.setattr("app.core.providers.adapters.openai.retrieve_provider_api_key", AsyncMock(return_value="provider-secret-placeholder"))
    monkeypatch.setattr("httpx.AsyncClient", _TimeoutClient)

    response = await AIProviderClient().chat_completion(_provider(ProviderType.openai), STANDARD_PAYLOAD)

    assert response.status_code == 504
    assert response.body["error"]["code"] == "read_timeout"


@pytest.mark.asyncio
async def test_phase_d_cancellation_is_not_converted_to_generic_500(monkeypatch):
    from app.core.engine.gateway import AIProviderClient

    monkeypatch.setattr("app.core.providers.adapters.openai.retrieve_provider_api_key", AsyncMock(return_value="provider-secret-placeholder"))
    monkeypatch.setattr("httpx.AsyncClient", _CancelledClient)

    with pytest.raises(asyncio.CancelledError):
        await AIProviderClient().chat_completion(_provider(ProviderType.openai), STANDARD_PAYLOAD)

# ─── LIVE TESTS (skip when credentials absent) ──────────────────────────────
# ===========================================================================

class TestOpenAIContractLive:
    """Live integration tests against OpenAI API."""

    @requires_openai
    @pytest.mark.asyncio
    async def test_sync_completion(self):
        provider = FakeProvider(ProviderType.openai, api_key=OPENAI_KEY)
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.openai)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
            "max_tokens": 10,
        })

        start = time.monotonic()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
        latency_ms = int((time.monotonic() - start) * 1000)

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        body = adapter.transform_response(resp.json())
        _openai_compat_response(body)
        assert latency_ms < 30_000, f"Too slow: {latency_ms}ms"
        print(f"\n[OpenAI SYNC] latency={latency_ms}ms content={body['choices'][0]['message']['content']!r}")

    @requires_openai
    @pytest.mark.asyncio
    async def test_streaming_completion(self):
        provider = FakeProvider(ProviderType.openai, api_key=OPENAI_KEY)
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.openai)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Count 1 2 3"}],
            "max_tokens": 20,
            "stream": True,
        })

        chunks = []
        first_chunk_ms = None
        start = time.monotonic()

        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as resp:
                assert resp.status_code == 200, f"HTTP {resp.status_code}"
                async for raw in adapter.stream_response(resp):
                    chunk = raw.decode("utf-8").strip()
                    if chunk.startswith("data: ") and chunk != "data: [DONE]":
                        if first_chunk_ms is None:
                            first_chunk_ms = int((time.monotonic() - start) * 1000)
                        chunks.append(chunk)

        assert len(chunks) > 0, "No stream chunks received"
        assert first_chunk_ms is not None, "Never got first chunk"
        print(f"\n[OpenAI STREAM] TTFT={first_chunk_ms}ms chunks={len(chunks)}")


class TestGroqContractLive:
    """Live integration tests against Groq API."""

    @requires_groq
    @pytest.mark.asyncio
    async def test_sync_completion(self):
        provider = FakeProvider(
            ProviderType.groq,
            api_key=GROQ_KEY,
            config={"base_url": "https://api.groq.com/openai/v1"}
        )
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.groq)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
            "max_tokens": 10,
        })

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        body = adapter.transform_response(resp.json())
        _openai_compat_response(body)
        print(f"\n[Groq SYNC] content={body['choices'][0]['message']['content']!r}")

    @requires_groq
    @pytest.mark.asyncio
    async def test_streaming_completion(self):
        provider = FakeProvider(
            ProviderType.groq,
            api_key=GROQ_KEY,
            config={"base_url": "https://api.groq.com/openai/v1"}
        )
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.groq)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": "Count 1 2 3"}],
            "max_tokens": 20,
            "stream": True,
        })

        chunks = []
        first_chunk_ms = None
        start = time.monotonic()

        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as resp:
                assert resp.status_code == 200
                async for raw in adapter.stream_response(resp):
                    chunk = raw.decode("utf-8").strip()
                    if chunk.startswith("data: ") and chunk != "data: [DONE]":
                        if first_chunk_ms is None:
                            first_chunk_ms = int((time.monotonic() - start) * 1000)
                        chunks.append(chunk)

        assert len(chunks) > 0, "No stream chunks received"
        print(f"\n[Groq STREAM] TTFT={first_chunk_ms}ms chunks={len(chunks)}")


class TestAnthropicContractLive:
    """Live integration tests against Anthropic API."""

    @requires_anthropic
    @pytest.mark.asyncio
    async def test_sync_completion(self):
        provider = FakeProvider(ProviderType.anthropic, api_key=ANTHROPIC_KEY)
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.anthropic)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "claude-3-haiku-20240307",
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
            "max_tokens": 10,
        })

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        body = adapter.transform_response(resp.json())
        _openai_compat_response(body)
        print(f"\n[Anthropic SYNC] content={body['choices'][0]['message']['content']!r}")

    @requires_anthropic
    @pytest.mark.asyncio
    async def test_streaming_completion(self):
        provider = FakeProvider(ProviderType.anthropic, api_key=ANTHROPIC_KEY)
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.anthropic)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "claude-3-haiku-20240307",
            "messages": [{"role": "user", "content": "Count 1 2 3"}],
            "max_tokens": 30,
            "stream": True,
        })

        chunks = []
        first_chunk_ms = None
        start = time.monotonic()

        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as resp:
                assert resp.status_code == 200
                async for raw in adapter.stream_response(resp):
                    chunk = raw.decode("utf-8").strip()
                    if chunk.startswith("data: ") and chunk != "data: [DONE]":
                        if first_chunk_ms is None:
                            first_chunk_ms = int((time.monotonic() - start) * 1000)
                        chunks.append(chunk)

        assert len(chunks) > 0, "No stream chunks received"
        print(f"\n[Anthropic STREAM] TTFT={first_chunk_ms}ms chunks={len(chunks)}")


class TestGeminiContractLive:
    """Live integration tests against Gemini API."""

    @requires_gemini
    @pytest.mark.asyncio
    async def test_sync_completion(self):
        provider = FakeProvider(ProviderType.gemini, api_key=GEMINI_KEY)
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.gemini)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "gemini-1.5-flash",
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
            "max_tokens": 10,
        })

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        body = adapter.transform_response(resp.json())
        _openai_compat_response(body)
        print(f"\n[Gemini SYNC] content={body['choices'][0]['message']['content']!r}")


class TestCohereContractLive:
    """Live integration tests against Cohere API."""

    @requires_cohere
    @pytest.mark.asyncio
    async def test_sync_completion(self):
        provider = FakeProvider(ProviderType.cohere, api_key=COHERE_KEY)
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.cohere)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": "command-r",
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
        })

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        body = adapter.transform_response(resp.json())
        _openai_compat_response(body)
        print(f"\n[Cohere SYNC] content={body['choices'][0]['message']['content']!r}")


class TestAzureOpenAIContractLive:
    """Live integration tests against Azure OpenAI API (API Key mode)."""

    @requires_azure
    @pytest.mark.asyncio
    async def test_sync_completion_api_key(self):
        azure_resource = os.environ.get("AZURE_OPENAI_RESOURCE_NAME", "")
        azure_deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT_ID", "gpt-4o-mini")
        if not azure_resource:
            pytest.skip("AZURE_OPENAI_RESOURCE_NAME not set")

        provider = FakeProvider(
            ProviderType.azure_openai,
            api_key=AZURE_KEY,
            config={
                "auth_type": "api_key",
                "azure_resource_name": azure_resource,
                "azure_deployment_id": azure_deployment,
                "azure_api_version": "2024-02-01",
            }
        )
        adapter = ProviderAdapterFactory.get_adapter(ProviderType.azure_openai)
        url, headers = await adapter.get_connection_details(provider)

        payload = adapter.transform_request({
            "model": azure_deployment,
            "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
            "max_tokens": 10,
        })

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"
        body = adapter.transform_response(resp.json())
        _openai_compat_response(body)
        print(f"\n[Azure SYNC] content={body['choices'][0]['message']['content']!r}")
