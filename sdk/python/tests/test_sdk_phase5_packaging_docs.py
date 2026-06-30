from __future__ import annotations

import importlib.util
import pathlib
import py_compile
import runpy
import tomllib

import authclaw
from authclaw import SDK_VERSION


SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_pyproject_metadata_and_dynamic_version() -> None:
    pyproject = tomllib.loads((SDK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    project = pyproject["project"]
    assert project["name"] == "authclaw"
    assert project["dynamic"] == ["version"]
    assert project["requires-python"] == ">=3.11"
    assert "requests>=2.31,<3" in project["dependencies"]
    assert "Topic :: Security" in project["classifiers"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"] == (
        "authclaw.version.SDK_VERSION"
    )


def test_version_metadata_is_consistent() -> None:
    assert SDK_VERSION == "0.1.0"
    assert authclaw.get_version().sdk_version == SDK_VERSION


def test_distribution_files_exist() -> None:
    for relative_path in ("README.md", "LICENSE", "CHANGELOG.md", "pyproject.toml"):
        path = SDK_ROOT / relative_path
        assert path.exists(), f"missing {relative_path}"
        assert path.read_text(encoding="utf-8").strip()


def test_root_readme_documents_required_topics() -> None:
    readme = (SDK_ROOT / "README.md").read_text(encoding="utf-8")

    for topic in (
        "Installation",
        "Authentication",
        "Configuration",
        "Chat Completions",
        "Streaming",
        "Retries",
        "Timeouts",
        "Error Handling",
        "Compatibility",
        "Versioning Policy",
        "Known Limitations",
    ):
        assert f"## {topic}" in readme


def test_examples_compile_and_use_public_sdk_interfaces() -> None:
    examples = sorted((SDK_ROOT / "examples").glob("*.py"))
    assert {path.name for path in examples} == {
        "chat_completion.py",
        "configuration.py",
        "health_check.py",
        "streaming_chat.py",
    }

    for path in examples:
        py_compile.compile(str(path), doraise=True)
        namespace = runpy.run_path(str(path), run_name=f"authclaw_example_{path.stem}")
        assert callable(namespace["main"])


def test_public_package_exports_packaging_phase_interfaces() -> None:
    expected_exports = {
        "AuthClawClient",
        "ApiKeyManager",
        "RetryPolicy",
        "RetryStrategy",
        "StreamingResponseIterator",
        "TransportStreamResponse",
        "SDK_VERSION",
    }

    assert expected_exports.issubset(set(authclaw.__all__))


def test_package_can_be_loaded_from_sdk_root() -> None:
    spec = importlib.util.find_spec("authclaw")
    assert spec is not None
    assert spec.origin is not None
    assert "sdk" in spec.origin
