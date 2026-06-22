from __future__ import annotations

import hashlib
import inspect
import json
import logging
import math
import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events.producer import producer as default_event_producer
from app.core.exceptions import NotFoundException
from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ControlRequirement,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeDocumentStatus,
    RetrievalTrace,
)
from app.schemas.events import (
    ComplianceKnowledgeRetrievedEvent,
    KnowledgeChunkCreatedEvent,
    KnowledgeDocumentIngestedEvent,
    KnowledgeDocumentUpdatedEvent,
)

logger = logging.getLogger(__name__)

COMPLIANCE_KNOWLEDGE_EVENTS_TOPIC = "authclaw.compliance.knowledge.events"
TARGET_CHUNK_CHARS = 3200
OVERLAP_CHARS = 300

SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws_secret_access_key|github_token|api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)
INSTRUCTION_PATTERNS = (
    re.compile(r"(?i)\bignore (all )?(previous|prior) instructions\b"),
    re.compile(r"(?i)\bdisregard (all )?(previous|prior) instructions\b"),
    re.compile(r"(?i)\byou are (now )?(chatgpt|an ai|a system prompt)\b"),
    re.compile(r"(?i)\bsystem prompt\b"),
    re.compile(r"(?i)\bexecute (this|the following|shell|command)\b"),
)
TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_\-]{2,}", re.IGNORECASE)
STOPWORDS = {
    "and",
    "are",
    "for",
    "from",
    "into",
    "not",
    "the",
    "this",
    "that",
    "with",
    "within",
    "should",
    "control",
    "controls",
    "evidence",
    "requirement",
}


@dataclass(frozen=True)
class KnowledgeIngestionResult:
    documents_seen: int
    documents_created: int
    documents_updated: int
    chunks_created: int


@dataclass(frozen=True)
class RetrievalChunkResult:
    chunk: KnowledgeChunk
    score: float
    citation: dict[str, Any]


@dataclass(frozen=True)
class RetrievalResult:
    query_hash: str
    confidence: float
    results: list[RetrievalChunkResult]
    trace: RetrievalTrace
    strategy: str = "lexical_fallback"


class ComplianceKnowledgeIngestionService:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer

    async def ingest_curated_catalog(
        self,
        tenant_id: uuid.UUID | str | None = None,
        ingested_by: uuid.UUID | str | None = None,
    ) -> KnowledgeIngestionResult:
        tenant_uuid = self._uuid(tenant_id) if tenant_id is not None else None
        ingested_by_uuid = self._uuid(ingested_by) if ingested_by is not None else None
        if tenant_uuid is not None:
            await self._set_tenant_context(tenant_uuid)

        frameworks = (
            await self.db.execute(
                select(ComplianceFramework)
                .where(ComplianceFramework.status == "active")
                .options(
                    selectinload(ComplianceFramework.controls)
                    .selectinload(ComplianceControl.requirements)
                )
                .order_by(ComplianceFramework.key, ComplianceFramework.version)
            )
        ).scalars().all()

        seen = created = updated = chunks_created = 0
        for framework in frameworks:
            doc_result = await self.ingest_document(
                tenant_id=tenant_uuid,
                framework_id=framework.id,
                control_id=None,
                source_type="framework_summary",
                title=f"{framework.name} summarized framework knowledge",
                source_url=framework.source_url,
                license_status="internal_summary_only",
                trust_level="curated",
                text=self._framework_text(framework),
                source_locator=f"framework:{framework.key}:{framework.version}",
                ingested_by=ingested_by_uuid,
                metadata={
                    "framework_key": framework.key,
                    "framework_version": framework.version,
                    "source": "phase1_compliance_catalog",
                },
            )
            seen += 1
            created += int(doc_result["created"])
            updated += int(doc_result["updated"])
            chunks_created += int(doc_result["chunks_created"])

            for control in sorted(framework.controls, key=lambda item: (item.sort_order, item.control_code)):
                doc_result = await self.ingest_document(
                    tenant_id=tenant_uuid,
                    framework_id=framework.id,
                    control_id=control.id,
                    source_type="control_summary",
                    title=f"{control.control_code}: {control.title}",
                    source_url=framework.source_url,
                    license_status="internal_summary_only",
                    trust_level="curated",
                    text=self._control_text(framework, control),
                    source_locator=f"control:{framework.key}:{control.control_code}",
                    ingested_by=ingested_by_uuid,
                    metadata={
                        "framework_key": framework.key,
                        "control_code": control.control_code,
                        "source": "phase1_compliance_catalog",
                    },
                )
                seen += 1
                created += int(doc_result["created"])
                updated += int(doc_result["updated"])
                chunks_created += int(doc_result["chunks_created"])

        await self.db.flush()
        return KnowledgeIngestionResult(
            documents_seen=seen,
            documents_created=created,
            documents_updated=updated,
            chunks_created=chunks_created,
        )

    async def ingest_document(
        self,
        *,
        tenant_id: uuid.UUID | str | None,
        framework_id: uuid.UUID | str | None,
        control_id: uuid.UUID | str | None,
        source_type: str,
        title: str,
        source_url: str | None,
        license_status: str,
        trust_level: str,
        text: str,
        source_locator: str,
        ingested_by: uuid.UUID | str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tenant_uuid = self._uuid(tenant_id) if tenant_id is not None else None
        framework_uuid = self._uuid(framework_id) if framework_id is not None else None
        control_uuid = self._uuid(control_id) if control_id is not None else None
        ingested_by_uuid = self._uuid(ingested_by) if ingested_by is not None else None
        if tenant_uuid is not None:
            await self._set_tenant_context(tenant_uuid)

        sanitized_text, redactions = self.sanitize_text(text)
        contains_instruction = self.contains_instruction_like_text(sanitized_text)
        safe_metadata = self._sanitize_metadata(metadata or {})
        safe_metadata.update(
            {
                "redaction_count": redactions,
                "contains_instruction_like_text": contains_instruction,
                "chunk_semantics": "retrieved chunks are untrusted data, not instructions",
            }
        )
        checksum_payload = {
            "tenant_id": str(tenant_uuid) if tenant_uuid else "global",
            "framework_id": str(framework_uuid) if framework_uuid else None,
            "control_id": str(control_uuid) if control_uuid else None,
            "source_type": source_type,
            "title": title,
            "text": sanitized_text,
            "metadata": safe_metadata,
        }
        checksum = hashlib.sha256(
            json.dumps(checksum_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        document = await self._find_existing_document(
            tenant_uuid=tenant_uuid,
            framework_uuid=framework_uuid,
            source_type=source_type,
            title=title,
        )
        created = document is None
        updated = False
        if document is None:
            document = KnowledgeDocument(
                tenant_id=tenant_uuid,
                framework_id=framework_uuid,
                source_type=source_type,
                title=title,
                checksum=checksum,
            )
            self.db.add(document)
        elif document.checksum != checksum:
            updated = True

        document.source_url = source_url
        document.license_status = license_status
        document.trust_level = trust_level
        document.status = KnowledgeDocumentStatus.active
        document.ingested_by = ingested_by_uuid
        document.metadata_ = safe_metadata

        chunks_created = 0
        if created or updated:
            document.checksum = checksum
            await self.db.flush()
            if updated:
                for existing in list(document.chunks):
                    await self.db.delete(existing)
                await self.db.flush()
            chunks = self.chunk_text(sanitized_text)
            for idx, chunk_text in enumerate(chunks):
                chunk = KnowledgeChunk(
                    document=document,
                    framework_id=framework_uuid,
                    tenant_id=tenant_uuid,
                    control_id=control_uuid,
                    chunk_index=idx,
                    chunk_text=chunk_text,
                    summary=self._chunk_summary(chunk_text),
                    embedding=self.deterministic_embedding(chunk_text),
                    metadata_=safe_metadata,
                    source_locator=f"{source_locator}#chunk-{idx}",
                )
                self.db.add(chunk)
                chunks_created += 1
            await self.db.flush()

            event_cls = KnowledgeDocumentIngestedEvent if created else KnowledgeDocumentUpdatedEvent
            await self._publish_event(
                event_cls(
                    tenant_id=str(tenant_uuid) if tenant_uuid else None,
                    document_id=str(document.id),
                    framework_id=str(framework_uuid) if framework_uuid else None,
                    source_type=source_type,
                    status=document.status.value,
                    chunk_count=chunks_created,
                    checksum=checksum,
                )
            )
            await self._publish_event(
                KnowledgeChunkCreatedEvent(
                    tenant_id=str(tenant_uuid) if tenant_uuid else None,
                    document_id=str(document.id),
                    framework_id=str(framework_uuid) if framework_uuid else None,
                    chunk_count=chunks_created,
                )
            )

        return {"document": document, "created": created, "updated": updated, "chunks_created": chunks_created}

    def chunk_text(self, text: str) -> list[str]:
        clean = text.strip()
        if len(clean) <= TARGET_CHUNK_CHARS:
            return [clean] if clean else []

        paragraphs = [part.strip() for part in re.split(r"\n{2,}", clean) if part.strip()]
        chunks: list[str] = []
        current = ""
        for paragraph in paragraphs:
            candidate = f"{current}\n\n{paragraph}".strip() if current else paragraph
            if len(candidate) <= TARGET_CHUNK_CHARS:
                current = candidate
                continue
            if current:
                chunks.append(current)
                current = self._overlap(current)
            while len(paragraph) > TARGET_CHUNK_CHARS:
                head = paragraph[:TARGET_CHUNK_CHARS].rsplit(" ", 1)[0] or paragraph[:TARGET_CHUNK_CHARS]
                chunks.append(head.strip())
                paragraph = f"{self._overlap(head)} {paragraph[len(head):]}".strip()
            current = f"{current}\n\n{paragraph}".strip() if current else paragraph
        if current:
            chunks.append(current)
        return chunks

    def sanitize_text(self, value: str) -> tuple[str, int]:
        redactions = 0
        sanitized = value or ""
        for pattern in SECRET_PATTERNS:
            sanitized, count = pattern.subn("[REDACTED_SECRET]", sanitized)
            redactions += count
        return sanitized, redactions

    def contains_instruction_like_text(self, value: str) -> bool:
        return any(pattern.search(value or "") for pattern in INSTRUCTION_PATTERNS)

    def deterministic_embedding(self, value: str) -> dict[str, Any]:
        digest = hashlib.sha256(value.encode("utf-8")).digest()
        vector = [round((byte / 255.0), 6) for byte in digest[:16]]
        return {"provider": "deterministic-local-fallback", "dimensions": 16, "vector": vector}

    async def _find_existing_document(
        self,
        *,
        tenant_uuid: uuid.UUID | None,
        framework_uuid: uuid.UUID | None,
        source_type: str,
        title: str,
    ) -> KnowledgeDocument | None:
        query = (
            select(KnowledgeDocument)
            .where(
                KnowledgeDocument.source_type == source_type,
                KnowledgeDocument.title == title,
            )
            .options(selectinload(KnowledgeDocument.chunks))
        )
        query = query.where(
            KnowledgeDocument.tenant_id.is_(None)
            if tenant_uuid is None
            else KnowledgeDocument.tenant_id == tenant_uuid
        )
        query = query.where(
            KnowledgeDocument.framework_id.is_(None)
            if framework_uuid is None
            else KnowledgeDocument.framework_id == framework_uuid
        )
        return (await self.db.execute(query)).scalars().first()

    def _framework_text(self, framework: ComplianceFramework) -> str:
        return "\n\n".join(
            [
                f"Framework: {framework.name}",
                f"Key: {framework.key}",
                f"Version: {framework.version}",
                f"Summary: {framework.description or 'Curated AuthClaw framework summary.'}",
                f"License note: {framework.license_note}",
                "Scope: This document contains AuthClaw-curated summaries only. It is not full licensed framework text.",
            ]
        )

    def _control_text(self, framework: ComplianceFramework, control: ComplianceControl) -> str:
        requirements = []
        for requirement in control.requirements:
            lines = [
                f"Requirement {requirement.requirement_key}: {requirement.summary}",
            ]
            if requirement.evidence_expectation:
                lines.append(f"Evidence expectation: {requirement.evidence_expectation}")
            requirements.append(" ".join(lines))
        return "\n\n".join(
            [
                f"Framework: {framework.name} ({framework.key})",
                f"Control: {control.control_code} - {control.title}",
                f"Domain: {control.domain}",
                f"Category: {control.category or 'general'}",
                f"Severity weight: {control.severity_weight}",
                f"Requires review: {control.requires_review}",
                f"Summary: {control.summary}",
                "Requirements:\n" + "\n".join(requirements),
                "Source boundary: AuthClaw-curated summary, not full licensed framework text.",
            ]
        )

    def _chunk_summary(self, value: str) -> str:
        return " ".join(value.split())[:280]

    def _overlap(self, value: str) -> str:
        return value[-OVERLAP_CHARS:].strip()

    def _sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        serialized = json.dumps(metadata, sort_keys=True, default=str)
        sanitized, _ = self.sanitize_text(serialized)
        return json.loads(sanitized)

    async def _publish_event(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(COMPLIANCE_KNOWLEDGE_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish compliance knowledge event %s: %s", event.event_type, exc)

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )


class ComplianceRetrievalService:
    def __init__(self, db: AsyncSession, event_producer=default_event_producer) -> None:
        self.db = db
        self.event_producer = event_producer

    async def retrieve(
        self,
        tenant_id: uuid.UUID | str,
        query: str,
        framework_id: uuid.UUID | str | None = None,
        control_id: uuid.UUID | str | None = None,
        limit: int = 5,
        session_id: str | None = None,
        trust_level: str | None = None,
    ) -> RetrievalResult:
        tenant_uuid = self._uuid(tenant_id)
        framework_uuid = self._uuid(framework_id) if framework_id is not None else None
        control_uuid = self._uuid(control_id) if control_id is not None else None
        await self._set_tenant_context(tenant_uuid)

        query_terms = self._tokens(query)
        chunk_query = (
            select(KnowledgeChunk)
            .join(KnowledgeDocument, KnowledgeChunk.document_id == KnowledgeDocument.id)
            .where(
                KnowledgeDocument.status == KnowledgeDocumentStatus.active,
                or_(KnowledgeDocument.tenant_id.is_(None), KnowledgeDocument.tenant_id == tenant_uuid),
                or_(KnowledgeChunk.tenant_id.is_(None), KnowledgeChunk.tenant_id == tenant_uuid),
            )
            .options(
                selectinload(KnowledgeChunk.document).selectinload(KnowledgeDocument.framework),
                selectinload(KnowledgeChunk.control),
            )
        )
        if framework_uuid is not None:
            chunk_query = chunk_query.where(KnowledgeChunk.framework_id == framework_uuid)
        if control_uuid is not None:
            chunk_query = chunk_query.where(KnowledgeChunk.control_id == control_uuid)
        if trust_level is not None:
            chunk_query = chunk_query.where(KnowledgeDocument.trust_level == trust_level)

        chunks = list((await self.db.execute(chunk_query)).scalars().all())
        ranked = sorted(
            (
                RetrievalChunkResult(
                    chunk=chunk,
                    score=self._lexical_score(query_terms, query, chunk),
                    citation=self._citation(chunk),
                )
                for chunk in chunks
            ),
            key=lambda item: (item.score, item.chunk.created_at),
            reverse=True,
        )
        results = [item for item in ranked if item.score > 0][: max(1, min(limit, 20))]
        if not results:
            results = ranked[: max(1, min(limit, 20))]

        trace = await self.create_retrieval_trace(
            tenant_id=tenant_uuid,
            query=query,
            framework_id=framework_uuid,
            filters={
                "control_id": str(control_uuid) if control_uuid else None,
                "limit": limit,
                "trust_level": trust_level,
                "strategy": "lexical_fallback",
            },
            results=results,
            session_id=session_id,
        )
        confidence = self._confidence(results)
        await self._publish_event(
            ComplianceKnowledgeRetrievedEvent(
                tenant_id=str(tenant_uuid),
                trace_id=str(trace.id),
                framework_id=str(framework_uuid) if framework_uuid else None,
                result_count=len(results),
                strategy="lexical_fallback",
                max_score=results[0].score if results else 0,
            )
        )
        return RetrievalResult(
            query_hash=trace.query_hash,
            confidence=confidence,
            results=results,
            trace=trace,
        )

    async def retrieve_for_control(
        self,
        tenant_id: uuid.UUID | str,
        control_id: uuid.UUID | str,
        query: str | None = None,
        limit: int = 5,
    ) -> RetrievalResult:
        control_uuid = self._uuid(control_id)
        control = await self.db.get(ComplianceControl, control_uuid)
        if control is None:
            raise NotFoundException(detail="Compliance control not found")
        effective_query = query or f"{control.control_code} {control.title} {control.summary}"
        return await self.retrieve(
            tenant_id=tenant_id,
            query=effective_query,
            framework_id=control.framework_id,
            control_id=control_uuid,
            limit=limit,
        )

    async def create_retrieval_trace(
        self,
        *,
        tenant_id: uuid.UUID,
        query: str,
        framework_id: uuid.UUID | None,
        filters: dict[str, Any],
        results: list[RetrievalChunkResult],
        session_id: str | None = None,
    ) -> RetrievalTrace:
        trace = RetrievalTrace(
            tenant_id=tenant_id,
            session_id=session_id,
            query_hash=hashlib.sha256(query.encode("utf-8")).hexdigest(),
            framework_id=framework_id,
            filters=self._sanitize_metadata(filters),
            chunk_ids=[str(item.chunk.id) for item in results],
            scores=[{"chunk_id": str(item.chunk.id), "score": item.score} for item in results],
            answer_confidence=None,
        )
        self.db.add(trace)
        await self.db.flush()
        return trace

    def _lexical_score(self, query_terms: set[str], query: str, chunk: KnowledgeChunk) -> float:
        chunk_terms = self._tokens(chunk.chunk_text)
        if not query_terms or not chunk_terms:
            return 0.0
        overlap = query_terms & chunk_terms
        score = len(overlap) / math.sqrt(len(query_terms) * len(chunk_terms))
        query_lower = query.lower()
        text_lower = chunk.chunk_text.lower()
        if query_lower and query_lower in text_lower:
            score += 1.0
        if chunk.document.trust_level == "curated":
            score *= 1.15
        if chunk.tenant_id is not None:
            score *= 1.25
        if chunk.metadata_.get("contains_instruction_like_text"):
            score *= 0.85
        return round(score, 6)

    def _citation(self, chunk: KnowledgeChunk) -> dict[str, Any]:
        document = chunk.document
        return {
            "document_id": str(document.id),
            "document_title": document.title,
            "source_locator": chunk.source_locator,
            "source_url": document.source_url,
            "license_status": document.license_status,
            "trust_level": document.trust_level,
            "framework_id": str(chunk.framework_id) if chunk.framework_id else None,
            "control_id": str(chunk.control_id) if chunk.control_id else None,
        }

    def _tokens(self, value: str) -> set[str]:
        return {
            token.lower()
            for token in TOKEN_PATTERN.findall(value or "")
            if token.lower() not in STOPWORDS
        }

    def _confidence(self, results: list[RetrievalChunkResult]) -> float:
        if not results:
            return 0.0
        return round(min(1.0, results[0].score), 4)

    def _sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        serialized = json.dumps(metadata, sort_keys=True, default=str)
        for pattern in SECRET_PATTERNS:
            serialized = pattern.sub("[REDACTED_SECRET]", serialized)
        return json.loads(serialized)

    async def _publish_event(self, event) -> None:
        if self.event_producer is None:
            return
        try:
            result = self.event_producer.publish(COMPLIANCE_KNOWLEDGE_EVENTS_TOPIC, event)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            logger.warning("Failed to publish compliance retrieval event %s: %s", event.event_type, exc)

    def _uuid(self, value: uuid.UUID | str) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))

    async def _set_tenant_context(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
