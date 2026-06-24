import uuid
import time
import json
import hashlib
import asyncio
import logging
from typing import Any, Dict, AsyncGenerator, Optional
import httpx
from fastapi.responses import StreamingResponse

from app.core.engine.audit import AuditEngine
from app.core.config import settings
from app.services.api_safety import sanitize_text

logger = logging.getLogger(__name__)


class StreamingMode:
    STRICT = "strict"
    BUFFERED = "buffered"
    PASSTHROUGH = "passthrough"


class StreamingEngine:
    def __init__(self, audit_engine: AuditEngine):
        self.audit_engine = audit_engine

    @staticmethod
    def _safe_sse_payload(payload: Dict[str, Any]) -> str:
        return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"

    @staticmethod
    def _done_sse() -> str:
        return "data: [DONE]\n\n"

    @staticmethod
    def _sanitize_request_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        sanitized_payload = dict(payload)
        messages = []
        for message in payload.get("messages", []):
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                messages.append({**message, "content": sanitize_text(message["content"])})
            else:
                messages.append(message)
        if messages:
            sanitized_payload["messages"] = messages
        sanitized_payload["stream"] = True
        return sanitized_payload

    @staticmethod
    def _extract_openai_delta(raw_chunk: bytes | str) -> tuple[Optional[str], bool]:
        chunk = raw_chunk.decode("utf-8") if isinstance(raw_chunk, bytes) else str(raw_chunk)
        chunk = chunk.strip()
        if not chunk:
            return None, False
        if not chunk.startswith("data: "):
            return None, False
        data_str = chunk[len("data: "):].strip()
        if data_str == "[DONE]":
            return None, True
        try:
            data_json = json.loads(data_str)
        except json.JSONDecodeError:
            return None, False
        choices = data_json.get("choices") or []
        if not choices:
            return None, False
        delta = choices[0].get("delta") or {}
        content = delta.get("content")
        return content if isinstance(content, str) else None, False

    async def _sanitize_stream_text(self, text: str) -> tuple[str, int]:
        sanitized = sanitize_text(text)
        entity_count = 1 if sanitized != text else 0
        if settings.FF_SECURITY_PIPELINE and settings.FF_STREAM_SCAN:
            from app.core.detection.presidio_engine import presidio_engine

            if not presidio_engine.is_healthy():
                raise RuntimeError("stream_security_scanner_unavailable")
            scan_result = await presidio_engine.scan(text)
            if scan_result.has_detections:
                sanitized = sanitize_text(scan_result.sanitized_text)
                entity_count = max(entity_count, len(scan_result.detections))
        return sanitized, entity_count

    async def _make_security_scan_fn(self, tenant_id: uuid.UUID, api_key_id: uuid.UUID):
        """
        Returns an async scan function compatible with StreamingBuffer.
        The function performs Presidio analysis on a text chunk and returns
        (sanitized_text, entity_count).
        Called once per stream setup — the closure captures the security engine.
        """
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.policy.cache import policy_cache
        from app.core.policy.evaluator import evaluator as policy_evaluator
        from app.schemas.security_events import PIIDetectedEvent, PHIDetectedEvent
        from app.core.events.producer import producer as event_producer

        # Pre-fetch compiled policy once for the stream lifetime
        # (avoids per-chunk Redis calls on the hot path)
        # Note: we can't await here; this is called at setup time in an async context
        compiled_policy = {}

        async def scan_fn(text: str):
            nonlocal compiled_policy
            # Lazy-load policy on first chunk
            if not compiled_policy:
                try:
                    from app.core.database import AsyncSessionLocal
                    async with AsyncSessionLocal() as db:
                        compiled_policy = await policy_cache.get(tenant_id, db)
                except Exception:
                    compiled_policy = {}

            if not presidio_engine.is_healthy():
                return text, 0  # Fail open on unhealthy engine

            scan_result = await presidio_engine.scan(text)
            entity_count = len(scan_result.detections)

            if scan_result.has_detections and not settings.FF_SECURITY_SHADOW_MODE:
                decision = policy_evaluator.evaluate(
                    detections=scan_result.detections,
                    text=text,
                    compiled_policy=compiled_policy,
                    shadow_mode=False,
                )
                return scan_result.sanitized_text, entity_count
            elif scan_result.has_detections:
                # Shadow mode: emit events but return original
                entity_types = scan_result.entity_types
                phi_entities = [et for et in entity_types if et.startswith("PHI_")]
                pii_entities = [et for et in entity_types if not et.startswith("PHI_")]
                if pii_entities:
                    asyncio.create_task(event_producer.publish_security_event(
                        PIIDetectedEvent(
                            event_type="completion.pii_detected",
                            tenant_id=str(tenant_id),
                            request_id=str(api_key_id),
                            direction="OUTBOUND",
                            shadow_mode=True,
                            payload={"entity_types": entity_types, "pii_entities": pii_entities},
                        )
                    ))
                return text, entity_count  # Shadow: return original

            return scan_result.sanitized_text if scan_result.has_detections else text, entity_count

        return scan_fn

    async def stream_response(
        self,
        tenant_id: uuid.UUID,
        api_key_id: uuid.UUID,
        provider_id: uuid.UUID,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        provider_name: str,
        adapter,
        streaming_mode: str = StreamingMode.BUFFERED,
        window_size: int = 20,
    ) -> StreamingResponse:
        stream_id = str(uuid.uuid4())
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        request_payload = adapter.transform_request(self._sanitize_request_payload(payload))

        async def event_generator() -> AsyncGenerator[str, None]:
            start_time = time.monotonic()

            full_response_chunks = []
            released_response = ""
            async with httpx.AsyncClient(timeout=60.0) as client:
                try:
                    async with client.stream("POST", url, headers=headers, json=request_payload) as response:
                        if response.status_code >= 400:
                            await self.audit_engine.publish_stream_failed(
                                stream_id=stream_id,
                                partial_response_hash=hashlib.sha256(b"").hexdigest(),
                                failure_reason="upstream_provider_stream_error",
                                policy_violation_details={"status_code": response.status_code},
                            )
                            yield self._safe_sse_payload({
                                "error": {
                                    "message": "Upstream provider streaming failed.",
                                    "type": "provider_error",
                                    "code": "upstream_stream_error",
                                }
                            })
                            yield self._done_sse()
                            return

                        await self.audit_engine.publish_stream_started(
                            stream_id=stream_id,
                            tenant_id=tenant_id,
                            api_key_id=api_key_id,
                            provider_id=provider_id,
                            security_mode=streaming_mode,
                            prompt_hash=prompt_hash,
                        )

                        async for raw_chunk in adapter.stream_response(response):
                            content, done = self._extract_openai_delta(raw_chunk)
                            if done:
                                break
                            if content:
                                full_response_chunks.append(content)

                        raw_response = "".join(full_response_chunks)
                        try:
                            sanitized_response, entity_count = await self._sanitize_stream_text(raw_response)
                        except Exception as scan_exc:
                            logger.error("Streaming response scan failed closed: %s", scan_exc)
                            await self.audit_engine.publish_stream_failed(
                                stream_id=stream_id,
                                partial_response_hash=hashlib.sha256(b"").hexdigest(),
                                failure_reason="stream_security_scan_failed",
                                policy_violation_details={"released": False},
                            )
                            yield self._safe_sse_payload({
                                "error": {
                                    "message": "Gateway stream security scan failed. Response was not released.",
                                    "type": "security_pipeline_error",
                                    "code": "stream_security_scan_failed",
                                }
                            })
                            yield self._done_sse()
                            return

                        released_response = sanitized_response
                        if sanitized_response:
                            yield self._safe_sse_payload({
                                "choices": [
                                    {
                                        "delta": {"content": sanitized_response},
                                        "index": 0,
                                        "finish_reason": None,
                                    }
                                ],
                                "authclaw": {
                                    "streaming_mode": "strict_buffered_safe",
                                    "redaction_applied": entity_count > 0,
                                    "entity_count": entity_count,
                                },
                            })
                        yield self._done_sse()

                        # Stream complete
                        latency_ms = int((time.monotonic() - start_time) * 1000)
                        response_hash = hashlib.sha256(released_response.encode()).hexdigest()

                        await self.audit_engine.publish_stream_completed(
                            stream_id=stream_id,
                            response_hash=response_hash,
                            prompt_tokens=0,
                            completion_tokens=len(full_response_chunks),
                            latency_ms=latency_ms,
                        )

                except Exception as e:
                    logger.error("STREAMING EXCEPTION: %s", e)
                    partial_response = released_response
                    partial_hash = hashlib.sha256(partial_response.encode()).hexdigest()
                    await self.audit_engine.publish_stream_failed(
                        stream_id=stream_id,
                        partial_response_hash=partial_hash,
                        failure_reason="streaming_error",
                        policy_violation_details=None,
                    )
                    yield self._safe_sse_payload({
                        "error": {
                            "message": "Gateway streaming failed safely.",
                            "type": "gateway_streaming_error",
                            "code": "streaming_error",
                        }
                    })
                    yield self._done_sse()

        return StreamingResponse(event_generator(), media_type="text/event-stream")
