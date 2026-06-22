#!/usr/bin/env bash
# ============================================================
# AuthClaw Gateway Load Test Runner
# ============================================================
# Usage:
#   bash apps/api/scripts/run_load_tests.sh
#
# Environment variables:
#   LOCUST_GATEWAY_TOKEN  - Bearer token for AuthClaw API key auth
#   LOCUST_USERS          - Number of concurrent users (default: 10)
#   LOCUST_SPAWN_RATE     - Users spawned per second (default: 2)
#   LOCUST_RUN_TIME       - Test duration e.g. 60s, 2m (default: 60s)
#   LOCUST_HOST           - Gateway host (default: http://localhost:8000)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_DIR="$(dirname "$SCRIPT_DIR")"

LOCUST_HOST="${LOCUST_HOST:-http://localhost:8000}"
LOCUST_USERS="${LOCUST_USERS:-10}"
LOCUST_SPAWN_RATE="${LOCUST_SPAWN_RATE:-2}"
LOCUST_RUN_TIME="${LOCUST_RUN_TIME:-60s}"
LOCUST_GATEWAY_TOKEN="${LOCUST_GATEWAY_TOKEN:-}"

if [ -z "$LOCUST_GATEWAY_TOKEN" ]; then
  echo "[ERROR] LOCUST_GATEWAY_TOKEN must be set"
  echo "  Export your gateway API key: export LOCUST_GATEWAY_TOKEN=<your-key>"
  exit 1
fi

echo "============================================"
echo "AuthClaw Gateway Load Test"
echo "  Host        : $LOCUST_HOST"
echo "  Users       : $LOCUST_USERS"
echo "  Spawn rate  : $LOCUST_SPAWN_RATE/s"
echo "  Duration    : $LOCUST_RUN_TIME"
echo "============================================"

REPORT_DIR="$API_DIR/docs/performance"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/load_test_$(date +%Y%m%d_%H%M%S).html"

cd "$API_DIR"

locust \
  -f tests/performance/locustfile.py \
  --host "$LOCUST_HOST" \
  --users "$LOCUST_USERS" \
  --spawn-rate "$LOCUST_SPAWN_RATE" \
  --run-time "$LOCUST_RUN_TIME" \
  --headless \
  --html "$REPORT_FILE" \
  --csv "$REPORT_DIR/load_test_$(date +%Y%m%d_%H%M%S)"

echo ""
echo "[+] Load test complete"
echo "[+] HTML report: $REPORT_FILE"
