"""
ClickHouse raw provider payload storage for connector findings.

This is the approved path for full provider JSON. PostgreSQL stores normalized
finding fields only.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Sequence

from app.core.clickhouse import get_clickhouse_client
from app.models.integration import CloudIntegration
from app.services.connectors.base import RawFindingData


class FindingRawStore:
    table_name = "security_finding_raw_payloads"

    async def store_batch(
        self,
        integration: CloudIntegration,
        scan_id: uuid.UUID,
        findings: Sequence[RawFindingData],
    ) -> None:
        if not findings:
            return
        client = await get_clickhouse_client()
        await self._ensure_table(client)
        rows = [
            (
                str(uuid.uuid4()),
                str(scan_id),
                str(integration.tenant_id),
                str(integration.id),
                integration.provider_type.value,
                finding.external_id,
                finding.resource_id,
                json.dumps(finding.raw_payload, default=str),
                datetime.now(timezone.utc),
            )
            for finding in findings
        ]
        await client.execute(
            f"""
            INSERT INTO {self.table_name}
            (id, scan_id, tenant_id, integration_id, provider_type,
             external_id, resource_id, raw_payload_json, created_at)
            VALUES
            """,
            *rows,
        )

    async def _ensure_table(self, client) -> None:
        await client.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table_name} (
                id String,
                scan_id String,
                tenant_id String,
                integration_id String,
                provider_type String,
                external_id String,
                resource_id String,
                raw_payload_json String,
                created_at DateTime64(3, 'UTC')
            )
            ENGINE = MergeTree
            ORDER BY (tenant_id, integration_id, created_at, external_id)
            """
        )

