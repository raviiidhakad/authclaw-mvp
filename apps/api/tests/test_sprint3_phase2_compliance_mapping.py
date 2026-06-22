from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, text

from app.api.v1.endpoints import compliance as compliance_api
from app.core.database import AsyncSessionLocal
from app.core.exceptions import NotFoundException
from app.models.compliance import (
    ComplianceControl,
    FindingControlMapping,
    MappingReviewStatus,
    MappingSource,
)
from app.models.finding import FindingSeverity, FindingStatus, SecurityFinding
from app.models.integration import CloudIntegration, CloudProvider, IntegrationStatus
from app.models.tenant import Tenant
from app.services.compliance_mapper import FindingControlMapper
from app.services.compliance_seed_loader import seed_compliance_catalog


class FakeProducer:
    def __init__(self):
        self.events = []

    async def publish(self, topic, event):
        self.events.append((topic, event.model_dump(mode="json")))


async def _tenant(db, suffix: str | None = None) -> Tenant:
    suffix = suffix or secrets.token_hex(5)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=f"sprint3-map-{suffix}",
        slug=f"sprint3-map-{suffix}",
        settings={},
    )
    db.add(tenant)
    await db.flush()
    return tenant


async def _integration(
    db,
    tenant_id: uuid.UUID,
    provider: CloudProvider,
    target: str | None = None,
) -> CloudIntegration:
    integration = CloudIntegration(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        provider_type=provider,
        target_identifier=target or f"target-{uuid.uuid4()}",
        display_name=f"{provider.value} test",
        status=IntegrationStatus.active,
        vault_reference_id=f"authclaw/tenants/{tenant_id}/integrations/{uuid.uuid4()}",
    )
    db.add(integration)
    await db.flush()
    return integration


async def _finding(
    db,
    integration_id: uuid.UUID,
    title: str,
    resource_id: str,
    provider_external_id: str | None = None,
    description: str = "",
    severity: FindingSeverity = FindingSeverity.high,
    status: FindingStatus = FindingStatus.active,
) -> SecurityFinding:
    finding = SecurityFinding(
        id=uuid.uuid4(),
        integration_id=integration_id,
        dedup_hash=(uuid.uuid4().hex + uuid.uuid4().hex)[:64],
        external_id=provider_external_id or f"finding-{uuid.uuid4()}",
        resource_id=resource_id,
        title=title,
        description=description,
        remediation_instructions="Review normalized finding and remediate safely.",
        severity=severity,
        status=status,
        resolved_at=datetime.utcnow() if status == FindingStatus.resolved else None,
    )
    db.add(finding)
    await db.flush()
    return finding


async def _cleanup(db, *tenant_ids: uuid.UUID) -> None:
    for tenant_id in tenant_ids:
        await db.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
            {"tenant_id": str(tenant_id)},
        )
        await db.execute(
            text("DELETE FROM finding_control_mappings WHERE tenant_id = :tenant_id"),
            {"tenant_id": tenant_id},
        )
        await db.execute(
            text(
                "DELETE FROM security_findings WHERE integration_id IN ("
                "SELECT id FROM cloud_integrations WHERE tenant_id = :tenant_id)"
            ),
            {"tenant_id": tenant_id},
        )
        await db.execute(
            text("DELETE FROM cloud_integrations WHERE tenant_id = :tenant_id"),
            {"tenant_id": tenant_id},
        )
        await db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": tenant_id})
    await db.commit()


async def _mapped_codes(db, mappings: list[FindingControlMapping]) -> set[str]:
    ids = [mapping.control_id for mapping in mappings]
    result = await db.execute(select(ComplianceControl.control_code).where(ComplianceControl.id.in_(ids)))
    return set(result.scalars().all())


@pytest.mark.asyncio
async def test_s3_public_bucket_maps_to_security_and_privacy_controls():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="S3 bucket allows public access",
                resource_id="arn:aws:s3:::customer-data-public",
                description="Public bucket policy detected",
            )

            mappings = await FindingControlMapper(db, event_producer=None).map_finding(
                tenant.id, finding.id
            )
            codes = await _mapped_codes(db, mappings)

            assert {"SOC2-SEC-ACCESS", "GDPR-SEC-32", "ISO27001-ACCESS"} <= codes
            assert all(mapping.confidence >= 0.9 for mapping in mappings)
            assert all(mapping.review_status == MappingReviewStatus.auto_approved for mapping in mappings)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_cloudtrail_mapping_targets_monitoring_and_audit_controls():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="CloudTrail is missing in account",
                resource_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/missing",
                description="No multi-region trail configured",
            )

            mappings = await FindingControlMapper(db, event_producer=None).map_finding(
                tenant.id, finding.id
            )
            codes = await _mapped_codes(db, mappings)

            assert {"SOC2-SEC-MONITOR", "HIPAA-TECH-AUDIT", "ISO27001-LOGGING"} <= codes
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_github_secret_and_iam_overpermission_mappings():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            github = await _integration(db, tenant.id, CloudProvider.github)
            secret_finding = await _finding(
                db,
                github.id,
                title="GitHub secret scanning alert exposed token",
                resource_id="acme/repo/security/secret-scanning/1",
                description="Credential exposure detected by GitHub",
                severity=FindingSeverity.critical,
            )
            aws = await _integration(db, tenant.id, CloudProvider.aws)
            iam_finding = await _finding(
                db,
                aws.id,
                title="IAM user has administrator over-permissioned policy",
                resource_id="arn:aws:iam::123456789012:user/admin",
                description="Wildcard admin privilege detected",
            )

            mapper = FindingControlMapper(db, event_producer=None)
            secret_codes = await _mapped_codes(db, await mapper.map_finding(tenant.id, secret_finding.id))
            iam_codes = await _mapped_codes(db, await mapper.map_finding(tenant.id, iam_finding.id))

            assert {"SOC2-SEC-ACCESS", "AC-AI-GW-POLICY"} <= secret_codes
            assert {"HIPAA-TECH-ACCESS", "ISO27001-ACCESS"} <= iam_codes
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_pii_phi_and_gcp_public_bucket_mappings():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            aws = await _integration(db, tenant.id, CloudProvider.aws)
            phi_finding = await _finding(
                db,
                aws.id,
                title="PHI leakage detected by AI gateway policy",
                resource_id="gateway-request-123",
                description="Patient health data was detected and redacted",
                severity=FindingSeverity.critical,
            )
            gcp = await _integration(db, tenant.id, CloudProvider.gcp)
            gcp_finding = await _finding(
                db,
                gcp.id,
                title="GCP public bucket allows allUsers access",
                resource_id="projects/p/buckets/public-storage",
                description="Cloud Storage bucket is public",
            )

            mapper = FindingControlMapper(db, event_producer=None)
            phi_codes = await _mapped_codes(db, await mapper.map_finding(tenant.id, phi_finding.id))
            gcp_codes = await _mapped_codes(db, await mapper.map_finding(tenant.id, gcp_finding.id))

            assert {"HIPAA-TECH-ACCESS", "HIPAA-TECH-AUDIT", "GDPR-ACC-5"} <= phi_codes
            assert {"SOC2-SEC-ACCESS", "GDPR-SEC-32", "ISO27001-ACCESS"} <= gcp_codes
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_mapping_is_idempotent_and_low_confidence_requires_review():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="Critical unknown cloud security exposure",
                resource_id="arn:aws:unknown:::resource",
                description="No specific deterministic rule should match this text",
                severity=FindingSeverity.critical,
            )
            mapper = FindingControlMapper(db, event_producer=None)

            first = await mapper.map_finding(tenant.id, finding.id)
            second = await mapper.map_finding(tenant.id, finding.id)
            count = await db.scalar(
                select(func.count(FindingControlMapping.id)).where(
                    FindingControlMapping.tenant_id == tenant.id,
                    FindingControlMapping.finding_id == finding.id,
                )
            )

            assert len(first) == len(second)
            assert count == len(first)
            assert all(mapping.confidence < 0.75 for mapping in first)
            assert all(mapping.review_status == MappingReviewStatus.needs_review for mapping in first)
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [FindingStatus.resolved, FindingStatus.suppressed])
async def test_resolved_and_suppressed_findings_remain_mappable(status):
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="S3 public bucket retained for compliance history",
                resource_id="arn:aws:s3:::historical-public-bucket",
                status=status,
            )

            mappings = await FindingControlMapper(db, event_producer=None).map_finding(
                tenant.id, finding.id
            )

            assert mappings
        finally:
            await _cleanup(db, tenant.id)


@pytest.mark.asyncio
async def test_mapper_enforces_tenant_scope_and_manual_override_is_preserved():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant_a = await _tenant(db, "a-" + secrets.token_hex(3))
        tenant_b = await _tenant(db, "b-" + secrets.token_hex(3))
        try:
            integration = await _integration(db, tenant_a.id, CloudProvider.aws)
            finding = await _finding(
                db,
                integration.id,
                title="S3 bucket public access",
                resource_id="arn:aws:s3:::tenant-a-public",
            )
            mapper = FindingControlMapper(db, event_producer=None)
            mappings = await mapper.map_finding(tenant_a.id, finding.id)

            with pytest.raises(NotFoundException):
                await mapper.map_finding(tenant_b.id, finding.id)

            assert await mapper.get_mappings_for_finding(tenant_b.id, finding.id) == []

            overridden = await mapper.override_mapping(
                tenant_a.id,
                mappings[0].id,
                review_status=MappingReviewStatus.rejected,
                confidence=0.4,
                override_reason="Auditor rejected this control relationship.",
            )
            assert overridden.mapping_source == MappingSource.manual
            assert overridden.review_status == MappingReviewStatus.rejected

            await mapper.remap_finding(tenant_a.id, finding.id)
            preserved = await db.get(FindingControlMapping, mappings[0].id)
            assert preserved.mapping_source == MappingSource.manual
            assert preserved.review_status == MappingReviewStatus.rejected
        finally:
            await _cleanup(db, tenant_a.id, tenant_b.id)


@pytest.mark.asyncio
async def test_mapping_events_and_read_api_are_safe_and_tenant_scoped():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        tenant = await _tenant(db)
        try:
            integration = await _integration(db, tenant.id, CloudProvider.github)
            finding = await _finding(
                db,
                integration.id,
                title="GitHub secret leak token=super-secret-token",
                resource_id="acme/repo/secret",
                description="raw_provider_payload github_token=super-secret-token",
                severity=FindingSeverity.critical,
            )
            producer = FakeProducer()
            mapper = FindingControlMapper(db, event_producer=producer)
            mappings = await mapper.map_finding(tenant.id, finding.id)

            assert producer.events
            serialized_events = str([event for _, event in producer.events]).lower()
            assert "super-secret-token" not in serialized_events
            assert "github_token" not in serialized_events
            assert "raw_provider_payload" not in serialized_events

            response = await compliance_api.list_mappings(
                skip=0,
                limit=50,
                framework="soc2",
                finding_id=finding.id,
                control_id=None,
                review_status=None,
                min_confidence=0.9,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )
            detail = await compliance_api.list_finding_mappings(
                finding.id,
                skip=0,
                limit=50,
                tenant=SimpleNamespace(id=tenant.id),
                _=SimpleNamespace(id=uuid.uuid4()),
                db=db,
            )

            assert response.items
            assert detail.total == len(mappings)
            assert "super-secret-token" not in str(response.model_dump(mode="json"))
        finally:
            await _cleanup(db, tenant.id)
