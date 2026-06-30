"""Informational AuthClaw SDK import benchmark.

This script is intentionally read-only. It measures import characteristics for
SDK closeout evidence and does not optimize or modify package behavior.
"""

from __future__ import annotations

import importlib
import json
import os
import pathlib
import subprocess
import sys
import time
import tomllib
from typing import Any


SDK_ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE_ROOT = SDK_ROOT / "authclaw"


def collect_import_metrics() -> dict[str, Any]:
    package_size_bytes = _package_size_bytes(PACKAGE_ROOT)
    dependencies = _project_dependencies(SDK_ROOT / "pyproject.toml")
    return {
        "cold_import_seconds": _measure_cold_import(),
        "warm_import_seconds": _measure_warm_import(),
        "package_size_bytes": package_size_bytes,
        "dependency_count": len(dependencies),
        "dependencies": dependencies,
        "package_root": str(PACKAGE_ROOT),
    }


def _measure_cold_import() -> float:
    code = (
        "import json, time; "
        "start = time.perf_counter(); "
        "import authclaw; "
        "print(json.dumps({'seconds': time.perf_counter() - start}))"
    )
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        str(SDK_ROOT)
        if not existing_pythonpath
        else str(SDK_ROOT) + os.pathsep + existing_pythonpath
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return float(json.loads(result.stdout)["seconds"])


def _measure_warm_import() -> float:
    if str(SDK_ROOT) not in sys.path:
        sys.path.insert(0, str(SDK_ROOT))
    importlib.import_module("authclaw")
    start = time.perf_counter()
    importlib.import_module("authclaw")
    return time.perf_counter() - start


def _package_size_bytes(package_root: pathlib.Path) -> int:
    total = 0
    for path in package_root.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts:
            total += path.stat().st_size
    return total


def _project_dependencies(pyproject_path: pathlib.Path) -> list[str]:
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    return list(pyproject["project"].get("dependencies", []))


def main() -> None:
    print(json.dumps(collect_import_metrics(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
