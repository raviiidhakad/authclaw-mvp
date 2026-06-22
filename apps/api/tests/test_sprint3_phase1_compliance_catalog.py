from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.v1.endpoints import compliance as compliance_api
from app.core.database import AsyncSessionLocal
from app.main import app
from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceScore,
    ControlRequirement,
    FrameworkSeedVersion,
)
from app.services.compliance_seed_loader import load_default_seed, seed_compliance_catalog


def test_phase1_models_extend_existing_compliance_score_without_replacing_it():
    assert ComplianceScore.__tablename__ == "compliance_scores"
    assert ComplianceFramework.__tablename__ == "compliance_frameworks"
    assert ComplianceControl.__tablename__ == "compliance_controls"
    assert ControlRequirement.__tablename__ == "control_requirements"
    assert FrameworkSeedVersion.__tablename__ == "framework_seed_versions"
    assert "tenant_id" not in ComplianceFramework.__table__.columns
    assert "tenant_id" not in ComplianceControl.__table__.columns


def test_default_seed_contains_required_frameworks_and_safe_summaries():
    seed, checksum = load_default_seed()
    keys = {framework["key"] for framework in seed["frameworks"]}
    assert {"gdpr", "hipaa", "soc2", "authclaw_ai_governance", "iso27001"} <= keys
    assert len(checksum) == 64

    serialized = str(seed).lower()
    forbidden_terms = [
        "aws_secret_access_key",
        "raw_provider_payload",
        "raw_payload",
        "github_token",
        "private_key",
    ]
    assert not any(term in serialized for term in forbidden_terms)
    assert "licensed" in serialized


@pytest.mark.asyncio
async def test_seed_loader_is_idempotent_and_tracks_checksum():
    async with AsyncSessionLocal() as db:
        first = await seed_compliance_catalog(db)
        second = await seed_compliance_catalog(db)

        assert first == second

        framework_count = await db.scalar(select(func.count(ComplianceFramework.id)))
        control_count = await db.scalar(select(func.count(ComplianceControl.id)))
        requirement_count = await db.scalar(select(func.count(ControlRequirement.id)))
        seed_count = await db.scalar(
            select(func.count(FrameworkSeedVersion.id)).where(
                FrameworkSeedVersion.seed_key == first.seed_key
            )
        )

    assert framework_count >= first.frameworks
    assert control_count >= first.controls
    assert requirement_count >= first.requirements
    assert seed_count == 1


@pytest.mark.asyncio
async def test_framework_listing_api_returns_seeded_catalog():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        response = await compliance_api.list_frameworks(
            framework=None,
            status="active",
            tenant=SimpleNamespace(id=uuid.uuid4()),
            _=SimpleNamespace(id=uuid.uuid4()),
            db=db,
        )

    keys = {item.key for item in response}
    assert {"gdpr", "hipaa", "soc2", "authclaw_ai_governance"} <= keys
    assert all(item.control_count > 0 for item in response)


@pytest.mark.asyncio
async def test_controls_listing_and_detail_api_are_read_only_and_sanitized():
    async with AsyncSessionLocal() as db:
        await seed_compliance_catalog(db)
        framework = (
            await db.execute(
                select(ComplianceFramework).where(ComplianceFramework.key == "gdpr")
            )
        ).scalars().first()
        assert framework is not None

        controls = await compliance_api.list_framework_controls(
            framework.id,
            skip=0,
            limit=20,
            domain="security",
            category=None,
            requires_review=None,
            search="Security",
            tenant=SimpleNamespace(id=uuid.uuid4()),
            _=SimpleNamespace(id=uuid.uuid4()),
            db=db,
        )
        assert controls.total >= 1

        detail = await compliance_api.get_control(
            controls.items[0].id,
            tenant=SimpleNamespace(id=uuid.uuid4()),
            _=SimpleNamespace(id=uuid.uuid4()),
            db=db,
        )

    payload = detail.model_dump(mode="json")
    serialized = str(payload).lower()
    assert payload["requirements"]
    assert "raw_payload" not in serialized
    assert "vault_reference_id" not in serialized
    assert "aws_secret_access_key" not in serialized


def test_framework_catalog_endpoint_requires_authentication():
    client = TestClient(app)
    response = client.get("/api/v1/compliance/frameworks")
    assert response.status_code == 401
