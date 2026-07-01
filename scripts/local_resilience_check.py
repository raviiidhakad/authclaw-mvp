from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_TCP_TARGETS = {
    "postgres": ("localhost", 5434),
    "redis": ("localhost", 6379),
    "redpanda_kafka": ("localhost", 19092),
    "vault": ("localhost", 8200),
    "clickhouse_http": ("localhost", 8123),
}

DEFAULT_HTTP_TARGETS = {
    "api_health": ("/health", {200}),
    "security_pipeline_health": ("/api/v1/health/security-pipeline", {200, 206}),
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    kind: str
    status: str
    target: str
    latency_ms: float
    detail: str


def tcp_check(name: str, host: str, port: int, timeout: float) -> CheckResult:
    started = time.perf_counter()
    target = f"{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = (time.perf_counter() - started) * 1000
            return CheckResult(name, "tcp", "pass", target, round(latency_ms, 3), "reachable")
    except OSError as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        return CheckResult(name, "tcp", "fail", target, round(latency_ms, 3), exc.__class__.__name__)


def http_check(name: str, url: str, allowed_statuses: Iterable[int], timeout: float) -> CheckResult:
    started = time.perf_counter()
    allowed = set(allowed_statuses)
    try:
        request = Request(url, headers={"Accept": "application/json"})
        with urlopen(request, timeout=timeout) as response:
            status_code = response.status
            body = response.read(4096).decode("utf-8", errors="replace")
        latency_ms = (time.perf_counter() - started) * 1000
        status = "pass" if status_code in allowed else "fail"
        return CheckResult(name, "http", status, url, round(latency_ms, 3), f"status={status_code}; body={body[:160]}")
    except HTTPError as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        status = "pass" if exc.code in allowed else "fail"
        return CheckResult(name, "http", status, url, round(latency_ms, 3), f"status={exc.code}")
    except (OSError, URLError) as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        return CheckResult(name, "http", "fail", url, round(latency_ms, 3), exc.__class__.__name__)


def run_checks(api_base_url: str, timeout: float) -> list[CheckResult]:
    base = api_base_url.rstrip("/")
    results: list[CheckResult] = []
    for name, (path, allowed_statuses) in DEFAULT_HTTP_TARGETS.items():
        results.append(http_check(name, f"{base}{path}", allowed_statuses, timeout))
    for name, (host, port) in DEFAULT_TCP_TARGETS.items():
        results.append(tcp_check(name, host, port, timeout))
    results.append(http_check("vault_sys_health", "http://localhost:8200/v1/sys/health", {200, 429, 472, 473, 501, 503}, timeout))
    results.append(http_check("clickhouse_ping", "http://localhost:8123/ping", {200}, timeout))
    return results


def summarize(results: list[CheckResult]) -> dict[str, object]:
    failed = [result for result in results if result.status != "pass"]
    return {
        "overall_status": "pass" if not failed else "fail",
        "failed": [result.name for result in failed],
        "checks": [asdict(result) for result in results],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run non-destructive AuthClaw local HA/resilience readiness checks.")
    parser.add_argument("--api-base-url", default="http://localhost:8000", help="Local AuthClaw API base URL.")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-check timeout in seconds.")
    parser.add_argument("--no-fail", action="store_true", help="Always exit 0 while still reporting failed checks.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    results = run_checks(args.api_base_url, args.timeout)
    summary = summarize(results)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.no_fail:
        return 0
    return 0 if summary["overall_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
