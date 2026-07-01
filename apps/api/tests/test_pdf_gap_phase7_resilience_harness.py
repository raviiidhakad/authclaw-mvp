from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "local_resilience_check.py"


def _load_harness():
    spec = importlib.util.spec_from_file_location("local_resilience_check", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_summary_marks_failed_checks_without_network_calls():
    harness = _load_harness()
    results = [
        harness.CheckResult("api_health", "http", "pass", "http://localhost:8000/health", 1.0, "status=200"),
        harness.CheckResult("redis", "tcp", "fail", "localhost:6379", 1.0, "ConnectionRefusedError"),
    ]

    summary = harness.summarize(results)

    assert summary["overall_status"] == "fail"
    assert summary["failed"] == ["redis"]
    assert summary["checks"][0]["name"] == "api_health"


def test_cli_no_fail_returns_success_when_checks_fail(monkeypatch, capsys):
    harness = _load_harness()

    monkeypatch.setattr(
        harness,
        "run_checks",
        lambda api_base_url, timeout: [
            harness.CheckResult("postgres", "tcp", "fail", "localhost:5434", 1.0, "ConnectionRefusedError")
        ],
    )

    exit_code = harness.main(["--no-fail"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert '"overall_status": "fail"' in output
    assert "postgres" in output


def test_cli_defaults_point_to_local_compose_ports():
    harness = _load_harness()

    assert harness.DEFAULT_TCP_TARGETS["postgres"] == ("localhost", 5434)
    assert harness.DEFAULT_TCP_TARGETS["redis"] == ("localhost", 6379)
    assert harness.DEFAULT_TCP_TARGETS["redpanda_kafka"] == ("localhost", 19092)
    assert harness.DEFAULT_TCP_TARGETS["vault"] == ("localhost", 8200)
    assert harness.DEFAULT_TCP_TARGETS["clickhouse_http"] == ("localhost", 8123)
