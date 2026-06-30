from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.core.audit.export_builder import (
    PHASE_2_DIGEST_PLACEHOLDER,
    AuditExportBuilder,
)
from app.core.audit.export_contracts import ExportPackagePath
from app.core.audit.repository import AuditRecord, AuditRepository


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("99999999-9999-4999-8999-999999999999")
EXPORT_ID = UUID("22222222-2222-4222-8222-222222222222")
REQUESTER_ID = UUID("33333333-3333-4333-8333-333333333333")
NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=1)
END = NOW + timedelta(hours=1)


class FakeAuditRepository(AuditRepository):
    def __init__(self, records: list[AuditRecord]) -> None:
        self.records = records
        self.export_calls: list[tuple[UUID, datetime, datetime]] = []

    async def append(self, record: AuditRecord) -> None:
        self.records.append(record)

    async def bulk_append(self, records: list[AuditRecord]) -> None:
        self.records.extend(records)

    async def list(self, tenant_id: UUID, limit: int = 100, offset: int = 0) -> list[AuditRecord]:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return scoped[offset : offset + limit]

    async def export(
        self,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> list[AuditRecord]:
        self.export_calls.append((tenant_id, start_date, end_date))
        return [
            record
            for record in self.records
            if record.tenant_id == tenant_id
            and start_date <= record.created_at <= end_date
        ]

    async def get_latest_hash(self, tenant_id: UUID) -> str | None:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return scoped[-1].integrity_hash if scoped else None

    async def get_latest_sequence_no(self, tenant_id: UUID) -> int:
        scoped = [record for record in self.records if record.tenant_id == tenant_id]
        return max((record.sequence_no for record in scoped), default=0)


class UnsafeFakeAuditRepository(FakeAuditRepository):
    async def export(
        self,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> list[AuditRecord]:
        self.export_calls.append((tenant_id, start_date, end_date))
        return list(self.records)


def _record(
    suffix: int,
    *,
    tenant_id: UUID = TENANT_ID,
    sequence_no: int | None = None,
    created_at: datetime | None = None,
    metadata: dict | None = None,
) -> AuditRecord:
    return AuditRecord(
        record_id=UUID(f"aaaaaaaa-aaaa-4aaa-8aaa-{suffix:012d}"),
        tenant_id=tenant_id,
        sequence_no=sequence_no if sequence_no is not None else suffix,
        created_at=created_at or (NOW + timedelta(seconds=suffix)),
        actor_id=REQUESTER_ID,
        actor_type="user",
        action="execute",
        frameworks_affected=["SOC2"],
        resource="gateway",
        resource_id=f"route-{suffix}",
        execution_trace="raw trace is intentionally not exported",
        metadata=metadata or {"event_type": "gateway.request", "safe": f"value-{suffix}"},
        ip_address="203.0.113.10",
        user_agent="pytest-agent",
        previous_hash=f"prev-{suffix}",
        integrity_hash=f"hash-{suffix}",
    )


async def _build(records: list[AuditRecord], **kwargs):
    repo = FakeAuditRepository(records)
    builder = AuditExportBuilder(repo, tool_version="0.9.0-test")
    result = await builder.build(
        tenant_id=TENANT_ID,
        start_date=START,
        end_date=END,
        export_id=EXPORT_ID,
        requester_id=REQUESTER_ID,
        created_at=NOW,
        purpose="compliance evidence",
        **kwargs,
    )
    return result, repo


@pytest.mark.asyncio
async def test_export_builder_constructs_empty_export():
    result, repo = await _build([])

    assert repo.export_calls == [(TENANT_ID, START, END)]
    assert result.export_id == EXPORT_ID
    assert result.tenant_id == TENANT_ID
    assert result.audit_records == ()
    assert result.files[ExportPackagePath.AUDIT.value] == ""
    assert result.manifest.record_count == 0
    assert result.manifest.chain_information.record_count == 0
    assert result.redaction_metrics["records_processed"] == 0


@pytest.mark.asyncio
async def test_export_builder_assembles_single_record_export():
    result, _ = await _build([_record(1)])

    assert len(result.audit_records) == 1
    audit_lines = result.files[ExportPackagePath.AUDIT.value].splitlines()
    assert len(audit_lines) == 1
    exported_record = json.loads(audit_lines[0])
    assert exported_record["record_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-000000000001"
    assert exported_record["tenant_id"] == str(TENANT_ID)
    assert exported_record["metadata"]["safe"] == "value-1"
    assert "execution_trace" not in exported_record
    assert result.manifest.chain_information.start_record_id == exported_record["record_id"]
    assert result.manifest.chain_information.end_record_id == exported_record["record_id"]
    assert result.chain_proof.chain_proof.record_range.record_count == 1


@pytest.mark.asyncio
async def test_export_builder_uses_canonical_record_ordering():
    newer = _record(2, created_at=NOW + timedelta(minutes=2), sequence_no=2)
    older = _record(1, created_at=NOW + timedelta(minutes=1), sequence_no=1)
    result, _ = await _build([newer, older])

    audit_lines = result.files[ExportPackagePath.AUDIT.value].splitlines()
    exported_ids = [json.loads(line)["record_id"] for line in audit_lines]

    assert exported_ids == [
        "aaaaaaaa-aaaa-4aaa-8aaa-000000000001",
        "aaaaaaaa-aaaa-4aaa-8aaa-000000000002",
    ]


@pytest.mark.asyncio
async def test_export_builder_enforces_tenant_isolation_if_repository_misbehaves():
    repo = UnsafeFakeAuditRepository([_record(1), _record(2, tenant_id=OTHER_TENANT_ID)])
    builder = AuditExportBuilder(repo)

    with pytest.raises(ValueError, match="cross-tenant"):
        await builder.build(
            tenant_id=TENANT_ID,
            start_date=START,
            end_date=END,
            export_id=EXPORT_ID,
            created_at=NOW,
        )


@pytest.mark.asyncio
async def test_export_builder_populates_manifest_with_phase_2_placeholders():
    result, _ = await _build([_record(1), _record(2)])
    manifest = result.manifest.model_dump(mode="json", by_alias=True)

    assert manifest["schema"] == "authclaw.audit.export/v1"
    assert manifest["package_version"] == 1
    assert manifest["manifest_version"] == 1
    assert manifest["tenant_id"] == str(TENANT_ID)
    assert manifest["export_id"] == str(EXPORT_ID)
    assert manifest["record_count"] == 2
    assert manifest["generator"] == "authclaw-audit-export-builder"
    assert manifest["tool_version"] == "0.9.0-test"
    assert set(manifest["file_digest_map"]) == {
        "audit.jsonl",
        "chain-proof.json",
        "config-snapshot.json",
        "manifest.json",
        "metadata.json",
        "redaction-metrics.json",
        "signature.sig",
    }
    assert all(
        entry["digest"] == PHASE_2_DIGEST_PLACEHOLDER
        for entry in manifest["file_digest_map"].values()
    )
    assert "chain-proof.json" in result.files
    assert "signature.sig" not in result.files


@pytest.mark.asyncio
async def test_export_builder_generates_metadata_and_config_snapshot():
    result, _ = await _build(
        [_record(1)],
        config_snapshot={
            "route": "gateway",
            "api_key": "should-not-export",
            "vault_ref": "vault://secret/path",
        },
    )

    metadata = json.loads(result.files[ExportPackagePath.METADATA.value])
    config = json.loads(result.files[ExportPackagePath.CONFIG_SNAPSHOT.value])

    assert metadata["tenant_id"] == str(TENANT_ID)
    assert metadata["export_id"] == str(EXPORT_ID)
    assert metadata["requester_id"] == str(REQUESTER_ID)
    assert metadata["tool_version"] == "0.9.0-test"
    assert config["runtime_behavior_changed"] is False
    assert config["hash_generation_enabled"] is False
    assert config["chain_proof_generation_enabled"] is True
    assert config["signature_generation_enabled"] is False
    assert config["zip_generation_enabled"] is False
    assert config["provided_config"]["route"] == "gateway"
    assert "api_key" not in config["provided_config"]
    assert "vault_ref" not in config["provided_config"]


@pytest.mark.asyncio
async def test_export_builder_reuses_export_sanitizer_for_sensitive_metadata():
    result, _ = await _build(
        [
            _record(
                1,
                metadata={
                    "event_type": "gateway.request",
                    "raw_provider_payload": {"secret": "bad"},
                    "authorization": "Bearer sk-should-not-export",
                    "message": "Bearer sk-demo-token-redacted",
                    "safe": "kept",
                },
            )
        ]
    )

    exported_record = json.loads(result.files[ExportPackagePath.AUDIT.value].splitlines()[0])
    serialized = json.dumps(result.files, sort_keys=True)

    assert exported_record["metadata"]["safe"] == "kept"
    assert "raw_provider_payload" not in exported_record["metadata"]
    assert "authorization" not in exported_record["metadata"]
    assert "sk-should-not-export" not in serialized
    assert "sk-demo-token-redacted" not in serialized
    assert result.redaction_metrics["records_processed"] == 1
    assert result.redaction_metrics["secret_values_exported"] is False


@pytest.mark.asyncio
async def test_export_builder_outputs_canonical_json_files():
    result, _ = await _build([_record(2), _record(1)])

    for path in (
        ExportPackagePath.MANIFEST.value,
        ExportPackagePath.METADATA.value,
        ExportPackagePath.CONFIG_SNAPSHOT.value,
        ExportPackagePath.REDACTION_METRICS.value,
    ):
        parsed = json.loads(result.files[path])
        assert result.files[path] == json.dumps(parsed, sort_keys=True, separators=(",", ":"), default=str)
