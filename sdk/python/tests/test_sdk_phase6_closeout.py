from __future__ import annotations

import importlib
import pathlib
import runpy
import tomllib

import authclaw
from authclaw import MINIMUM_AUTHCLAW_VERSION, SDK_VERSION, SUPPORTED_API_VERSION


SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SDK_ROOT.parents[1]
CLOSEOUT_DOC = REPO_ROOT / "docs" / "developer-sdk-closeout.md"


def test_package_import_and_public_exports_are_stable() -> None:
    imported = importlib.import_module("authclaw")
    required_exports = {
        "ApiKeyManager",
        "AuthClawClient",
        "AuthClawConfig",
        "AuthClawError",
        "ChatCompletionRequestContract",
        "RetryPolicy",
        "SdkSseParser",
        "StreamingRequestContract",
        "StreamingResponseIterator",
        "Transport",
    }

    assert imported is authclaw
    assert required_exports.issubset(set(authclaw.__all__))


def test_version_and_packaging_metadata_are_consistent() -> None:
    pyproject = tomllib.loads((SDK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert SDK_VERSION == "0.1.0"
    assert SUPPORTED_API_VERSION == "v1"
    assert MINIMUM_AUTHCLAW_VERSION == "0.11.0"
    assert pyproject["project"]["name"] == "authclaw"
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"] == (
        "authclaw.version.SDK_VERSION"
    )


def test_examples_remain_import_safe() -> None:
    for path in sorted((SDK_ROOT / "examples").glob("*.py")):
        namespace = runpy.run_path(str(path), run_name=f"authclaw_closeout_{path.stem}")
        assert callable(namespace["main"])


def test_documentation_references_required_sdk_topics() -> None:
    root_readme = (SDK_ROOT / "README.md").read_text(encoding="utf-8")
    package_readme = (SDK_ROOT / "authclaw" / "README.md").read_text(encoding="utf-8")
    closeout = CLOSEOUT_DOC.read_text(encoding="utf-8")

    for topic in (
        "Authentication",
        "Configuration",
        "Chat Completions",
        "Streaming",
        "Retries",
        "Timeouts",
        "Error Handling",
        "Compatibility",
    ):
        assert topic in root_readme

    assert "SDK-side streaming support" in package_readme
    assert "Compatibility Matrix" in closeout
    assert "Known Limitations" in closeout


def test_compatibility_matrix_is_explicit() -> None:
    closeout = CLOSEOUT_DOC.read_text(encoding="utf-8")

    for expected in (
        "Python >=3.11",
        "AuthClaw >=0.11.0",
        "API v1",
        "Synchronous client",
        "OpenAI-compatible chat completions",
    ):
        assert expected in closeout


def test_import_benchmark_collects_informational_metrics() -> None:
    namespace = runpy.run_path(str(SDK_ROOT / "benchmark_sdk_import.py"))
    metrics = namespace["collect_import_metrics"]()

    assert metrics["cold_import_seconds"] >= 0
    assert metrics["warm_import_seconds"] >= 0
    assert metrics["package_size_bytes"] > 0
    assert metrics["dependency_count"] == 1
    assert metrics["dependencies"] == ["requests>=2.31,<3"]
