from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ControlRequirement,
    FrameworkSeedVersion,
)

DEFAULT_SEED_RESOURCE = "framework_catalog_v1.json"


@dataclass(frozen=True)
class ComplianceSeedResult:
    seed_key: str
    checksum: str
    frameworks: int
    controls: int
    requirements: int


def load_default_seed() -> tuple[dict[str, Any], str]:
    seed_path = files("app.compliance.seeds").joinpath(DEFAULT_SEED_RESOURCE)
    seed_bytes = seed_path.read_bytes()
    checksum = hashlib.sha256(seed_bytes).hexdigest()
    return json.loads(seed_bytes.decode("utf-8")), checksum


async def seed_compliance_catalog(db: AsyncSession) -> ComplianceSeedResult:
    seed_data, checksum = load_default_seed()
    seed_key = str(seed_data["seed_key"])
    framework_count = 0
    control_count = 0
    requirement_count = 0

    for framework_payload in seed_data.get("frameworks", []):
        framework = await _upsert_framework(db, framework_payload)
        framework_count += 1

        for control_payload in framework_payload.get("controls", []):
            control = await _upsert_control(db, framework, control_payload)
            control_count += 1

            for requirement_payload in control_payload.get("requirements", []):
                await _upsert_requirement(db, control, requirement_payload)
                requirement_count += 1

    await _upsert_seed_version(
        db,
        seed_key=seed_key,
        checksum=checksum,
        framework_count=framework_count,
        control_count=control_count,
        requirement_count=requirement_count,
        metadata={"version": seed_data.get("version")},
    )
    await db.commit()

    return ComplianceSeedResult(
        seed_key=seed_key,
        checksum=checksum,
        frameworks=framework_count,
        controls=control_count,
        requirements=requirement_count,
    )


async def _upsert_framework(
    db: AsyncSession,
    payload: dict[str, Any],
) -> ComplianceFramework:
    result = await db.execute(
        select(ComplianceFramework)
        .where(
            ComplianceFramework.key == payload["key"],
            ComplianceFramework.version == payload["version"],
        )
        .options(selectinload(ComplianceFramework.controls))
    )
    framework = result.scalars().first()
    if framework is None:
        framework = ComplianceFramework(
            key=payload["key"],
            version=payload["version"],
            name=payload["name"],
            license_note=payload["license_note"],
        )
        db.add(framework)

    framework.name = payload["name"]
    framework.description = payload.get("description")
    framework.source_url = payload.get("source_url")
    framework.license_note = payload["license_note"]
    framework.status = payload.get("status", "active")
    framework.metadata_ = payload.get("metadata", {})
    await db.flush()
    return framework


async def _upsert_control(
    db: AsyncSession,
    framework: ComplianceFramework,
    payload: dict[str, Any],
) -> ComplianceControl:
    result = await db.execute(
        select(ComplianceControl).where(
            ComplianceControl.framework_id == framework.id,
            ComplianceControl.control_code == payload["control_code"],
        )
    )
    control = result.scalars().first()
    if control is None:
        control = ComplianceControl(
            framework_id=framework.id,
            control_code=payload["control_code"],
            title=payload["title"],
            summary=payload["summary"],
            domain=payload["domain"],
        )
        db.add(control)

    control.title = payload["title"]
    control.summary = payload["summary"]
    control.domain = payload["domain"]
    control.category = payload.get("category")
    control.severity_weight = int(payload.get("severity_weight", 1))
    control.requires_review = bool(payload.get("requires_review", False))
    control.sort_order = int(payload.get("sort_order", 0))
    control.metadata_ = payload.get("metadata", {})
    await db.flush()
    return control


async def _upsert_requirement(
    db: AsyncSession,
    control: ComplianceControl,
    payload: dict[str, Any],
) -> ControlRequirement:
    result = await db.execute(
        select(ControlRequirement).where(
            ControlRequirement.control_id == control.id,
            ControlRequirement.requirement_key == payload["requirement_key"],
        )
    )
    requirement = result.scalars().first()
    if requirement is None:
        requirement = ControlRequirement(
            control_id=control.id,
            requirement_key=payload["requirement_key"],
            summary=payload["summary"],
        )
        db.add(requirement)

    requirement.summary = payload["summary"]
    requirement.evidence_expectation = payload.get("evidence_expectation")
    requirement.sort_order = int(payload.get("sort_order", 0))
    await db.flush()
    return requirement


async def _upsert_seed_version(
    db: AsyncSession,
    seed_key: str,
    checksum: str,
    framework_count: int,
    control_count: int,
    requirement_count: int,
    metadata: dict[str, Any],
) -> FrameworkSeedVersion:
    result = await db.execute(
        select(FrameworkSeedVersion).where(FrameworkSeedVersion.seed_key == seed_key)
    )
    seed_version = result.scalars().first()
    if seed_version is None:
        seed_version = FrameworkSeedVersion(seed_key=seed_key, checksum=checksum)
        db.add(seed_version)

    seed_version.checksum = checksum
    seed_version.framework_count = framework_count
    seed_version.control_count = control_count
    seed_version.requirement_count = requirement_count
    seed_version.metadata_ = metadata
    await db.flush()
    return seed_version
