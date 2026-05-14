#!/usr/bin/env bash
# deploy/run_gateway.sh — ETP Gateway VM deploy orchestration
#
# Steps:
#   1. Load deploy/.env.gateway (fail if missing)
#   2. Run preflight checks via deploy/preflight_gateway.py
#   3. Build and start the gateway container (docker compose)
#   4. Poll /gateway/health up to 30 s; fail on timeout
#   5. Pretty-print status JSON, show endpoint URLs, tail logs

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.gateway"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.gateway.yml"
PREFLIGHT_SCRIPT="${SCRIPT_DIR}/preflight_gateway.py"

# ---------------------------------------------------------------------------
# Step 1 — Load env file
# ---------------------------------------------------------------------------
echo ""
echo "==> [1/5] Loading environment from ${ENV_FILE}"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo ""
    echo "ERROR: ${ENV_FILE} not found."
    echo ""
    echo "  Create it from the example template:"
    echo "    cp ${SCRIPT_DIR}/.env.gateway.example ${ENV_FILE}"
    echo "  Then fill in the required values:"
    echo "    ETP_GATEWAY_VM_SOURCE_RPC_URL"
    echo "    ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT"
    echo "    ETP_GATEWAY_VM_DEST_RPC_URL"
    echo "    ETP_GATEWAY_VM_DEST_REGISTRY"
    echo "    ETP_GATEWAY_VM_OPERATOR_KEY"
    echo ""
    echo "  For FedRAMP High readiness, start from:"
    echo "    config/fedramp-high.env.template"
    echo ""
    exit 1
fi

set -a
# shellcheck source=/dev/null
source "${ENV_FILE}"
set +a

echo "    OK — env loaded."

# Resolve gateway port (default 8000 if not set)
ETP_GATEWAY_PORT="${ETP_GATEWAY_PORT:-8000}"

# ---------------------------------------------------------------------------
# Step 2 — Pre-flight checks
# ---------------------------------------------------------------------------
echo ""
echo "==> [2/5] Running pre-flight checks (${PREFLIGHT_SCRIPT})"

if ! python3 "${PREFLIGHT_SCRIPT}"; then
    echo ""
    echo "ERROR: Pre-flight checks failed. Fix the issues above before deploying."
    exit 1
fi

echo "    OK — all pre-flight checks passed."

# ---------------------------------------------------------------------------
# Step 3 — Build and start
# ---------------------------------------------------------------------------
echo ""
echo "==> [3/5] Building and starting gateway container"
echo "    docker compose -f ${COMPOSE_FILE} up --build -d"

docker compose -f "${COMPOSE_FILE}" up --build -d

echo "    OK — container started."

# ---------------------------------------------------------------------------
# Step 4 — Health wait (up to 30 s)
# ---------------------------------------------------------------------------
echo ""
echo "==> [4/5] Waiting for gateway to become healthy"

HEALTH_URL="http://localhost:${ETP_GATEWAY_PORT}/gateway/health"
TIMEOUT=30
POLL_INTERVAL=2
ELAPSED=0

echo "    Polling ${HEALTH_URL} (timeout: ${TIMEOUT}s) ..."

while true; do
    if curl -sf "${HEALTH_URL}" > /dev/null 2>&1; then
        echo "    OK — gateway is healthy (${ELAPSED}s)."
        break
    fi

    if [[ "${ELAPSED}" -ge "${TIMEOUT}" ]]; then
        echo ""
        echo "ERROR: Gateway did not become healthy within ${TIMEOUT} seconds."
        echo ""
        echo "  Container logs:"
        docker compose -f "${COMPOSE_FILE}" logs --tail=40 gateway
        exit 1
    fi

    sleep "${POLL_INTERVAL}"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
done

# ---------------------------------------------------------------------------
# Step 5 — Status summary
# ---------------------------------------------------------------------------
echo ""
echo "==> [5/5] Gateway status"

STATUS_URL="http://localhost:${ETP_GATEWAY_PORT}/gateway/status"
echo "    Status: ${STATUS_URL}"
echo ""

# Pretty-print status JSON; tolerate if the endpoint isn't available yet
if curl -sf "${STATUS_URL}" | python3 -m json.tool; then
    echo ""
else
    echo "    (status endpoint not available — gateway may still be initializing)"
fi

ETP_GATEWAY_VM_METRICS_PORT="${ETP_GATEWAY_VM_METRICS_PORT:-9090}"

echo "------------------------------------------------------------"
echo "  Gateway API:     http://localhost:${ETP_GATEWAY_PORT}"
echo "  Health:          http://localhost:${ETP_GATEWAY_PORT}/gateway/health"
echo "  Status:          http://localhost:${ETP_GATEWAY_PORT}/gateway/status"
echo "  Metrics:         http://localhost:${ETP_GATEWAY_VM_METRICS_PORT}/metrics"
echo "  Docs (Swagger):  http://localhost:${ETP_GATEWAY_PORT}/docs"
echo "------------------------------------------------------------"
echo ""
echo "  Tailing logs (Ctrl-C to stop) ..."
echo ""

docker compose -f "${COMPOSE_FILE}" logs -f gateway
