from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudProvider
from app.services.findings_context import FindingContextRow, FindingsContextBuilder


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


@dataclass
class MemoryRecord:
    tenant_id: uuid.UUID
    status: FindingStatus
    row: FindingContextRow


class MemoryFindingsContextBuilder(FindingsContextBuilder):
    def __init__(self, records, producer=None):
        super().__init__(db=None, event_producer=producer)
        self.records = records

    async def _fetch_active_findings(
        self,
        tenant_id,
        integration_id=None,
        provider_type=None,
    ):
        rows = []
        for record in self.records:
            if record.tenant_id != tenant_id:
                continue
            if record.status != FindingStatus.active:
                continue
            if integration_id is not None and record.row.integration_id != integration_id:
                continue
            if provider_type is not None and record.row.provider_type != provider_type:
                continue
            rows.append(record.row)
        return rows


def make_record(
    *,
    tenant_id,
    integration_id=None,
    provider=CloudProvider.aws,
    severity=FindingSeverity.low,
    status=FindingStatus.active,
    title="Finding",
    description="Normalized description",
    resource_id="arn:aws:s3:::bucket",
    updated_at=None,
    dedup_hash=None,
):
    integration_id = integration_id or uuid.uuid4()
    finding = SecurityFinding(
        integration_id=integration_id,
        dedup_hash=dedup_hash or uuid.uuid4().hex + uuid.uuid4().hex,
        external_id=f"external-{uuid.uuid4()}",
        resource_id=resource_id,
        title=title,
        description=description,
        remediation_instructions="Apply least privilege remediation.",
        severity=severity,
        status=status,
        created_at=updated_at or datetime.now(timezone.utc),
        updated_at=updated_at or datetime.now(timezone.utc),
    )
    return MemoryRecord(
        tenant_id=tenant_id,
        status=status,
        row=FindingContextRow(
            finding=finding,
            provider_type=provider,
            integration_id=integration_id,
        ),
    )


@pytest.mark.asyncio
async def test_builds_context_for_tenant_with_active_findings():
    tenant_id = uuid.uuid4()
    builder = MemoryFindingsContextBuilder(
        [
            make_record(
                tenant_id=tenant_id,
                severity=FindingSeverity.high,
                title="Public S3 bucket",
            )
        ]
    )

    context = await builder.build_for_tenant(tenant_id)

    assert len(context) == 1
    assert context[0].startswith("[HIGH]")
    assert "provider=aws" in context[0]
    assert "service=s3" in context[0]
    assert "Public S3 bucket" in context[0]


@pytest.mark.asyncio
async def test_excludes_resolved_findings_and_other_tenants():
    tenant_id = uuid.uuid4()
    other_tenant = uuid.uuid4()
    builder = MemoryFindingsContextBuilder(
        [
            make_record(tenant_id=tenant_id, status=FindingStatus.resolved),
            make_record(tenant_id=other_tenant, severity=FindingSeverity.critical),
            make_record(tenant_id=tenant_id, severity=FindingSeverity.medium),
        ]
    )

    context = await builder.build_for_tenant(tenant_id)

    assert len(context) == 1
    assert context[0].startswith("[MEDIUM]")


@pytest.mark.asyncio
async def test_sorts_critical_before_high_medium_low():
    tenant_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    builder = MemoryFindingsContextBuilder(
        [
            make_record(tenant_id=tenant_id, severity=FindingSeverity.low, title="Low"),
            make_record(tenant_id=tenant_id, severity=FindingSeverity.high, title="High"),
            make_record(
                tenant_id=tenant_id,
                severity=FindingSeverity.critical,
                title="Critical",
                updated_at=now - timedelta(days=1),
            ),
            make_record(tenant_id=tenant_id, severity=FindingSeverity.medium, title="Medium"),
        ]
    )

    context = await builder.build_for_tenant(tenant_id)

    assert [item.split("]")[0] + "]" for item in context] == [
        "[CRITICAL]",
        "[HIGH]",
        "[MEDIUM]",
        "[LOW]",
    ]


@pytest.mark.asyncio
async def test_respects_max_agent_context_findings(monkeypatch):
    tenant_id = uuid.uuid4()
    monkeypatch.setattr("app.services.findings_context.settings.MAX_AGENT_CONTEXT_FINDINGS", 2)
    builder = MemoryFindingsContextBuilder(
        [
            make_record(tenant_id=tenant_id, severity=FindingSeverity.critical),
            make_record(tenant_id=tenant_id, severity=FindingSeverity.high),
            make_record(tenant_id=tenant_id, severity=FindingSeverity.medium),
        ]
    )

    context = await builder.build_for_tenant(tenant_id, limit=99)

    assert len(context) == 2
    assert context[0].startswith("[CRITICAL]")
    assert context[1].startswith("[HIGH]")


@pytest.mark.asyncio
async def test_builds_context_for_specific_integration():
    tenant_id = uuid.uuid4()
    wanted = uuid.uuid4()
    builder = MemoryFindingsContextBuilder(
        [
            make_record(tenant_id=tenant_id, integration_id=wanted, title="Wanted"),
            make_record(tenant_id=tenant_id, integration_id=uuid.uuid4(), title="Ignored"),
        ]
    )

    context = await builder.build_for_integration(tenant_id, wanted)

    assert len(context) == 1
    assert "Wanted" in context[0]
    assert "Ignored" not in str(context)


@pytest.mark.asyncio
async def test_builds_context_for_specific_provider():
    tenant_id = uuid.uuid4()
    builder = MemoryFindingsContextBuilder(
        [
            make_record(tenant_id=tenant_id, provider=CloudProvider.github, title="GitHub issue"),
            make_record(tenant_id=tenant_id, provider=CloudProvider.gcp, title="GCP issue"),
        ]
    )

    context = await builder.build_for_provider(tenant_id, "github")

    assert len(context) == 1
    assert "provider=github" in context[0]
    assert "GitHub issue" in context[0]


@pytest.mark.asyncio
async def test_returns_safe_empty_list_when_no_active_findings():
    builder = MemoryFindingsContextBuilder([])

    assert await builder.build_for_tenant(uuid.uuid4()) == []


@pytest.mark.asyncio
async def test_output_excludes_raw_payload_labels_and_credential_like_strings():
    tenant_id = uuid.uuid4()
    builder = MemoryFindingsContextBuilder(
        [
            make_record(
                tenant_id=tenant_id,
                title="raw_finding_data github_token leaked",
                description=(
                    "aws_secret_access_key=very-secret "
                    "AKIAIOSFODNN7EXAMPLE "
                    "github_pat_abcdefghijklmnopqrstuvwxyz"
                ),
            )
        ]
    )

    context = await builder.build_for_tenant(tenant_id)
    output = str(context)

    assert "raw_finding_data" not in output
    assert "github_token" not in output
    assert "aws_secret_access_key" not in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output
    assert "github_pat_abcdefghijklmnopqrstuvwxyz" not in output
    assert "[redacted]" in output


@pytest.mark.asyncio
async def test_event_emitted_when_context_is_built():
    tenant_id = uuid.uuid4()
    producer = FakeProducer()
    builder = MemoryFindingsContextBuilder(
        [
            make_record(
                tenant_id=tenant_id,
                provider=CloudProvider.aws,
                severity=FindingSeverity.critical,
            )
        ],
        producer=producer,
    )

    await builder.build_for_tenant(tenant_id)

    assert len(producer.events) == 1
    topic, event = producer.events[0]
    assert topic == "authclaw.agent.events"
    assert event["event_type"] == "agent.context.built"
    assert event["tenant_id"] == str(tenant_id)
    assert event["finding_count"] == 1
    assert event["max_severity"] == "critical"
    assert event["provider_types"] == ["aws"]
