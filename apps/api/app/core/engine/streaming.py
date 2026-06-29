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
from app.core.engine.sse_parser import ParsedSseEvent, SseParser
from app.core.engine.streaming_state_machine import StreamingRedactionStateMachine
from app.core.engine.utf8_decoder import Utf8IncrementalDecoder
from app.core.config import settings
from app.services.api_safety import sanitize_text

logger = logging.getLogger(__name__)


class StreamingMode:
    STRICT = "strict"
    BUFFERED = "buffered"
    PASSTHROUGH = "passthrough"


class StreamingSecurityBlocked(RuntimeError):
    """Raised when outbound streaming content is blocked by existing policy."""

    def __init__(self, reason: str) -> None:
        super().__init__("streaming_security_blocked")
        self.reason = sanitize_text(reason)


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
        return StreamingEngine._extract_openai_delta_data(data_str)

    @staticmethod
    def _extract_openai_delta_data(data_str: str) -> tuple[Optional[str], bool]:
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

    @staticmethod
    def _normalize_legacy_sse_text(text: str) -> str:
        stripped = text.strip()
        if "\n" in text or not stripped.startswith("data: "):
            return text
        data_str = stripped[len("data: "):].strip()
        if data_str == "[DONE]":
            return text + "\n\n"
        try:
            json.loads(data_str)
        except json.JSONDecodeError:
            return text
        return text + "\n\n"

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

    async def _apply_stream_security(
        self,
        tenant_id: uuid.UUID,
        api_key_id: uuid.UUID,
        text: str,
    ) -> tuple[str, int]:
        if not (settings.FF_SECURITY_PIPELINE and settings.FF_STREAM_SCAN):
            return await self._sanitize_stream_text(text)

        from app.core.database import AsyncSessionLocal
        from app.core.detection.classification import classifier
        from app.core.detection.presidio_engine import presidio_engine
        from app.core.events.producer import producer as event_producer
        from app.core.policy.cache import policy_cache
        from app.core.policy.evaluator import evaluator as policy_evaluator
        from app.schemas.security_events import (
            ContentRedactedEvent,
            PHIDetectedEvent,
            PIIDetectedEvent,
            PolicyEvaluatedEvent,
            ResponseBlockedEvent,
        )

        if not presidio_engine.is_healthy():
            raise RuntimeError("stream_security_scanner_unavailable")

        async with AsyncSessionLocal() as db:
            compiled_policy = await policy_cache.get(tenant_id, db)

        scan_result = await presidio_engine.scan(text)
        decision = policy_evaluator.evaluate(
            detections=scan_result.detections,
            text=text,
            compiled_policy=compiled_policy,
            shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
        )
        entity_count = len(scan_result.detections)

        if scan_result.has_detections or decision.keyword_hits:
            entity_actions = compiled_policy.get("entity_actions", {})
            reversible_entities = compiled_policy.get("reversible_entities", [])
            classification_overrides = compiled_policy.get("classification_overrides", {})
            entity_types = scan_result.entity_types
            max_risk = classifier.max_risk(entity_types, classification_overrides) if entity_types else None
            pii_entities = [item for item in entity_types if not item.startswith("PHI_")]
            phi_entities = [item for item in entity_types if item.startswith("PHI_")]
            detection_payload = {
                "entity_types": entity_types,
                "max_risk_level": max_risk.value if max_risk else "UNKNOWN",
                "detection_count": entity_count,
                "latency_presidio_ms": scan_result.latency_ms,
                "policy_action": decision.action.value,
                "shadow_mode": settings.FF_SECURITY_SHADOW_MODE,
                "keyword_hits": decision.keyword_hits,
            }

            if pii_entities:
                asyncio.create_task(event_producer.publish_security_event(
                    PIIDetectedEvent(
                        event_type="completion.pii_detected",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                        payload={**detection_payload, "pii_entities": pii_entities},
                    )
                ))
            if phi_entities:
                asyncio.create_task(event_producer.publish_security_event(
                    PHIDetectedEvent(
                        event_type="completion.phi_detected",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                        payload={**detection_payload, "phi_entities": phi_entities},
                    )
                ))
            asyncio.create_task(event_producer.publish_security_event(
                PolicyEvaluatedEvent(
                    event_type="policy.evaluated",
                    tenant_id=str(tenant_id),
                    request_id=str(api_key_id),
                    direction="OUTBOUND",
                    shadow_mode=settings.FF_SECURITY_SHADOW_MODE,
                    payload={
                        "policies_evaluated": len(compiled_policy.get("policy_ids", [])) or 1,
                        "rules_evaluated": len(compiled_policy.get("entity_actions", {})),
                        "violations_found": len(decision.violations),
                        "evaluation_ms": scan_result.latency_ms,
                        "action": decision.action.value,
                    },
                )
            ))

            if decision.should_block:
                asyncio.create_task(event_producer.publish_security_event(
                    ResponseBlockedEvent(
                        event_type="response.blocked",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=False,
                        payload={
                            "block_reason": decision.block_reason or "Completion blocked by tenant policy.",
                            "entity_types": entity_types,
                            "keyword_hits": decision.keyword_hits,
                        },
                    )
                ))
                raise StreamingSecurityBlocked(decision.block_reason or "Completion blocked by tenant policy.")

            if decision.should_redact and scan_result.detections:
                from app.core.engine.gateway import GatewayService

                transformed, redaction_mode = await GatewayService._apply_redaction(
                    text,
                    scan_result.detections,
                    scan_result.sanitized_text,
                    "NONE",
                    entity_actions,
                    reversible_entities,
                    tenant_id,
                )
                asyncio.create_task(event_producer.publish_security_event(
                    ContentRedactedEvent(
                        event_type="completion.redacted",
                        tenant_id=str(tenant_id),
                        request_id=str(api_key_id),
                        direction="OUTBOUND",
                        shadow_mode=False,
                        payload={
                            "redaction_mode": redaction_mode,
                            "entities_redacted": decision.redact_entities or entity_types,
                            "entity_count": entity_count,
                        },
                    )
                ))
                return transformed, entity_count

        return scan_result.sanitized_text if scan_result.has_detections else sanitize_text(text), entity_count

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

                        decoder = Utf8IncrementalDecoder()
                        parser = SseParser()
                        state_machine = StreamingRedactionStateMachine(max_window_chars=max(window_size, 20) * 1024)
                        completion_chunks_seen = 0
                        done = False

                        async for raw_chunk in adapter.stream_response(response):
                            if isinstance(raw_chunk, str):
                                decoded_text = raw_chunk
                            else:
                                decoded_text = decoder.decode(raw_chunk)
                            if not decoded_text:
                                continue

                            decoded_text = self._normalize_legacy_sse_text(decoded_text)
                            for event in parser.feed(decoded_text):
                                if event.data is None:
                                    continue
                                content, done = self._extract_openai_delta_data(event.data.strip())
                                if done:
                                    break
                                if content:
                                    completion_chunks_seen += 1
                                    state_machine.append(ParsedSseEvent(data=content))
                                    for window in state_machine.emit_safe():
                                        full_response_chunks.append(window.text)
                            if done:
                                break

                        if not done:
                            decoded_text = decoder.flush()
                            if decoded_text:
                                for event in parser.feed(self._normalize_legacy_sse_text(decoded_text)):
                                    if event.data is None:
                                        continue
                                    content, done = self._extract_openai_delta_data(event.data.strip())
                                    if done:
                                        break
                                    if content:
                                        completion_chunks_seen += 1
                                        state_machine.append(ParsedSseEvent(data=content))
                                        for window in state_machine.emit_safe():
                                            full_response_chunks.append(window.text)
                                    if done:
                                        break
                        if not done:
                            parser.flush()
                        state_machine.end_of_stream()
                        for window in state_machine.flush():
                            full_response_chunks.append(window.text)

                        raw_response = "".join(full_response_chunks)
                        try:
                            sanitized_response, entity_count = await self._apply_stream_security(
                                tenant_id,
                                api_key_id,
                                raw_response,
                            )
                        except StreamingSecurityBlocked as blocked_exc:
                            await self.audit_engine.publish_stream_failed(
                                stream_id=stream_id,
                                partial_response_hash=hashlib.sha256(b"").hexdigest(),
                                failure_reason="stream_policy_blocked",
                                policy_violation_details={"released": False},
                            )
                            yield self._safe_sse_payload({
                                "error": {
                                    "message": "Response blocked by AuthClaw security policy.",
                                    "type": "security_policy_violation",
                                    "code": "response_blocked",
                                    "block_reason": blocked_exc.reason,
                                }
                            })
                            yield self._done_sse()
                            return
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
                            completion_tokens=completion_chunks_seen,
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
