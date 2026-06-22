"""
PostgreSQL inventory persistence for normalized connector findings.

Raw provider payloads are intentionally excluded. They are written to
FindingRawStore/ClickHouse; this service stores only normalized fields needed by
the product and agent context.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration
from app.services.connectors.base import RawFindingData


@dataclass
class FindingPersistenceResult:
    created: int = 0
    updated: int = 0
    resolved: int = 0


class FindingInventoryService:
    def make_dedup_hash(
        self,
        integration_id: uuid.UUID,
        external_id: str,
        resource_id: str,
    ) -> str:
        key = f"{integration_id}:{external_id}:{resource_id}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    async def persist_scan_results(
        self,
        db: AsyncSession,
        integration: CloudIntegration,
        findings: Sequence[RawFindingData],
        scan_started_at: datetime,
    ) -> FindingPersistenceResult:
        result = FindingPersistenceResult()
        seen_hashes: set[str] = set()
        now = datetime.now(timezone.utc)

        for raw in findings:
            dedup_hash = self.make_dedup_hash(
                integration.id,
                raw.external_id,
                raw.resource_id,
            )
            seen_hashes.add(dedup_hash)
            existing = await self._find_by_hash(db, dedup_hash)
            if existing is None:
                db.add(
                    SecurityFinding(
                        integration_id=integration.id,
                        dedup_hash=dedup_hash,
                        external_id=raw.external_id,
                        resource_id=raw.resource_id,
                        title=raw.title,
                        description=raw.description,
                        remediation_instructions=raw.remediation_instructions,
                        severity=raw.severity,
                        status=FindingStatus.new,
                        updated_at=now,
                    )
                )
                result.created += 1
                continue

            existing.external_id = raw.external_id
            existing.resource_id = raw.resource_id
            existing.title = raw.title
            existing.description = raw.description
            existing.remediation_instructions = raw.remediation_instructions
            existing.severity = raw.severity
            existing.updated_at = now
            if existing.status == FindingStatus.resolved:
                existing.status = FindingStatus.active
                existing.resolved_at = None
            result.updated += 1

        stale = await self._find_stale_active(db, integration.id, scan_started_at)
        for finding in stale:
            if finding.dedup_hash in seen_hashes:
                continue
            finding.status = FindingStatus.resolved
            finding.resolved_at = now
            finding.updated_at = now
            result.resolved += 1

        await db.flush()
        return result

    async def _find_by_hash(
        self,
        db: AsyncSession,
        dedup_hash: str,
    ) -> SecurityFinding | None:
        query = select(SecurityFinding).where(SecurityFinding.dedup_hash == dedup_hash)
        return (await db.execute(query)).scalar_one_or_none()

    async def _find_stale_active(
        self,
        db: AsyncSession,
        integration_id: uuid.UUID,
        scan_started_at: datetime,
    ) -> list[SecurityFinding]:
        query = select(SecurityFinding).where(
            SecurityFinding.integration_id == integration_id,
            SecurityFinding.status == FindingStatus.active,
            SecurityFinding.updated_at < scan_started_at,
        )
        return list((await db.execute(query)).scalars().all())

