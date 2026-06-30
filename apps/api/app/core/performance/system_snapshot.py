"""
E4.3 environment and system snapshot helpers.

These helpers capture generic host metadata for benchmark interpretation. They
do not inspect AuthClaw runtime services or connect to infrastructure.
"""
from __future__ import annotations

import os
import platform
import sys
from datetime import UTC, datetime
from uuid import uuid4

from app.core.performance.benchmark_contracts import BenchmarkEnvironmentContract
from app.core.performance.performance_types import (
    HardwareMetadataContract,
    SoftwareVersionContract,
)


def hardware_snapshot() -> HardwareMetadataContract:
    """Return best-effort local hardware metadata using standard library calls."""

    return HardwareMetadataContract(
        cpu_model=platform.processor() or None,
        cpu_cores=os.cpu_count() or None,
        memory_bytes=None,
        machine_type=platform.machine() or None,
    )


def software_snapshot(*, authclaw_version: str | None = None) -> SoftwareVersionContract:
    """Return software metadata relevant to benchmark result interpretation."""

    return SoftwareVersionContract(
        authclaw_version=authclaw_version,
        python_version=platform.python_version(),
        os=f"{platform.system()} {platform.release()}",
    )


def environment_snapshot(
    *,
    name: str = "local",
    authclaw_version: str | None = None,
) -> BenchmarkEnvironmentContract:
    """Build a serializable benchmark environment contract."""

    return BenchmarkEnvironmentContract(
        environment_id=uuid4(),
        name=name,
        captured_at=datetime.now(UTC),
        hardware=hardware_snapshot(),
        software=software_snapshot(authclaw_version=authclaw_version),
        metadata={
            "python_executable": sys.executable,
            "snapshot_source": "standard_library",
        },
    )

