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

logger = logging.getLogger(__name__)


class StreamingMode:
    STRICT = "strict"
    BUFFERED = "buffered"
    PASSTHROUGH = "passthrough"


class StreamingEngine:
    def __init__(self, audit_engine: AuditEngine):
        self.audit_engine = audit_engine

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

        request_payload = adapter.transform_request(payload)

        # ── Sprint 1: Build StreamingBuffer if FF_STREAM_SCAN is active ─────
        stream_buffer = None
        if settings.FF_SECURITY_PIPELINE and settings.FF_STREAM_SCAN:
            try:
                from app.core.detection.presidio_engine import presidio_engine
                from app.core.detection.streaming_buffer import StreamingBuffer

                if presidio_engine.is_healthy():
                    scan_fn = await self._make_security_scan_fn(tenant_id, api_key_id)
                    stream_buffer = StreamingBuffer(
                        scan_fn=scan_fn,
                        buffer_size=settings.STREAMING_BUFFER_SIZE,
                        shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                    )
                    logger.debug("StreamingBuffer activated for stream %s", stream_id)
            except Exception as exc:
                logger.warning("StreamingBuffer setup failed, falling back to passthrough: %s", exc)
                stream_buffer = None

        async def event_generator() -> AsyncGenerator[str, None]:
            start_time = time.monotonic()

            async with httpx.AsyncClient(timeout=60.0) as client:
                try:
                    async with client.stream("POST", url, headers=headers, json=request_payload) as response:
                        if response.status_code >= 400:
                            await response.aread()
                            logger.error("PROVIDER ERROR: %s", response.text)
                        response.raise_for_status()

                        await self.audit_engine.publish_stream_started(
                            stream_id=stream_id,
                            tenant_id=tenant_id,
                            api_key_id=api_key_id,
                            provider_id=provider_id,
                            security_mode=streaming_mode,
                            prompt_hash=prompt_hash,
                        )

                        full_response_chunks = []
                        token_buffer = []

                        async def raw_content_stream():
                            """Yields only the text content tokens from the SSE stream."""
                            async for raw_chunk in adapter.stream_response(response):
                                chunk = raw_chunk.decode("utf-8")
                                if not chunk:
                                    continue
                                if chunk.startswith("data: "):
                                    data_str = chunk[len("data: "):].strip()
                                    if data_str == "[DONE]":
                                        return
                                    try:
                                        data_json = json.loads(data_str)
                                        if "choices" in data_json and len(data_json["choices"]) > 0:
                                            delta = data_json["choices"][0].get("delta", {})
                                            content = delta.get("content", "")
                                            if content:
                                                yield content
                                    except json.JSONDecodeError:
                                        pass

                        if stream_buffer and streaming_mode == StreamingMode.BUFFERED:
                            # ── Real StreamingBuffer path ────────────────────
                            async for sanitized_chunk in stream_buffer.process(raw_content_stream()):
                                full_response_chunks.append(sanitized_chunk)
                                # Re-wrap in SSE format for client
                                sse_chunk = json.dumps({
                                    "choices": [{"delta": {"content": sanitized_chunk}, "index": 0}]
                                })
                                yield f"data: {sse_chunk}\n\n"
                            yield "data: [DONE]\n\n"

                        else:
                            # ── Legacy path (passthrough or no buffer) ───────
                            async for raw_chunk in adapter.stream_response(response):
                                chunk = raw_chunk.decode("utf-8")
                                if not chunk:
                                    continue
                                if chunk.startswith("data: "):
                                    data_str = chunk[len("data: "):].strip()
                                    if data_str == "[DONE]":
                                        yield f"data: [DONE]\n\n"
                                        break
                                    try:
                                        data_json = json.loads(data_str)
                                        content = ""
                                        if "choices" in data_json and len(data_json["choices"]) > 0:
                                            delta = data_json["choices"][0].get("delta", {})
                                            content = delta.get("content", "")

                                        if content:
                                            full_response_chunks.append(content)
                                            token_buffer.append((content, chunk))

                                            if streaming_mode == StreamingMode.PASSTHROUGH:
                                                yield f"{chunk}\n\n"
                                                token_buffer.clear()

                                            elif streaming_mode == StreamingMode.BUFFERED:
                                                if len(token_buffer) >= window_size:
                                                    for _, original_chunk in token_buffer:
                                                        yield f"{original_chunk}\n\n"
                                                    token_buffer.clear()

                                    except json.JSONDecodeError:
                                        pass

                            # Flush remaining tokens in legacy buffered mode
                            if streaming_mode == StreamingMode.BUFFERED and token_buffer:
                                for _, original_chunk in token_buffer:
                                    yield f"{original_chunk}\n\n"

                        # Stream complete
                        latency_ms = int((time.monotonic() - start_time) * 1000)
                        full_response = "".join(full_response_chunks)
                        response_hash = hashlib.sha256(full_response.encode()).hexdigest()

                        await self.audit_engine.publish_stream_completed(
                            stream_id=stream_id,
                            response_hash=response_hash,
                            prompt_tokens=0,
                            completion_tokens=len(full_response_chunks),
                            latency_ms=latency_ms,
                        )

                except Exception as e:
                    logger.error("STREAMING EXCEPTION: %s", e)
                    partial_response = "".join(full_response_chunks) if 'full_response_chunks' in locals() else ""
                    partial_hash = hashlib.sha256(partial_response.encode()).hexdigest()
                    await self.audit_engine.publish_stream_failed(
                        stream_id=stream_id,
                        partial_response_hash=partial_hash,
                        failure_reason=str(e),
                        policy_violation_details=None,
                    )
                    raise

        return StreamingResponse(event_generator(), media_type="text/event-stream")

