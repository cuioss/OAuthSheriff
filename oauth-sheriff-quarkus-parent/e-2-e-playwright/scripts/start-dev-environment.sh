#!/usr/bin/env bash
# Start the E2E Dev-UI test environment:
# 1. Start Keycloak via docker compose
# 2. Start Quarkus dev mode for the integration-tests module
# 3. Wait for both to be ready
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"
INTEGRATION_TESTS_DIR="$MODULE_DIR/../oauth-sheriff-quarkus-integration-tests"
PROJECT_ROOT="$MODULE_DIR/../.."
TARGET_DIR="$MODULE_DIR/target"

mkdir -p "$TARGET_DIR"

echo "=== Starting E2E Dev-UI Test Environment ==="

# --- Step 1: Start Keycloak ---
echo "[1/3] Starting Keycloak..."
cd "$MODULE_DIR"
docker compose up -d

echo "[1/3] Waiting for Keycloak health..."
KEYCLOAK_HEALTH_URL="https://localhost:1090/health/ready"
MAX_WAIT=90
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -sk "$KEYCLOAK_HEALTH_URL" 2>/dev/null | grep -q '"status".*"UP"'; then
        echo "[1/3] Keycloak is ready (${WAITED}s)"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "[1/3] Still waiting for Keycloak... (${WAITED}s/${MAX_WAIT}s)"
    fi
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "[1/3] ERROR: Keycloak did not become ready within ${MAX_WAIT}s"
    docker compose logs keycloak
    exit 1
fi

# --- Step 2: Start Quarkus Dev Mode ---
echo "[2/3] Starting Quarkus dev mode..."
cd "$INTEGRATION_TESTS_DIR"

# Start Quarkus dev mode in the background
# Disable interactive console and ANSI colors to prevent hangs in CI
"$PROJECT_ROOT/mvnw" quarkus:dev \
    -Dquarkus.analytics.disabled=true \
    -Dquarkus.test.continuous-testing=disabled \
    -Dquarkus.dev-ui.cors.enabled=true \
    -Dquarkus.console.enabled=false \
    -Dquarkus.log.console.color=false \
    < /dev/null > "$TARGET_DIR/quarkus-dev.log" 2>&1 &

QUARKUS_PID=$!
echo "$QUARKUS_PID" > "$TARGET_DIR/quarkus-dev.pid"
echo "[2/3] Quarkus dev mode started (PID: $QUARKUS_PID)"

# --- Step 3: Wait for Quarkus Dev-UI ---
echo "[3/3] Waiting for Quarkus Dev-UI..."
DEVUI_URL="http://localhost:8080/q/dev-ui/"
MAX_WAIT=120
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    # Check if the process is still running
    if ! kill -0 "$QUARKUS_PID" 2>/dev/null; then
        echo "[3/3] ERROR: Quarkus dev mode process died"
        echo "Last 50 lines of log:"
        tail -50 "$TARGET_DIR/quarkus-dev.log"
        exit 1
    fi

    if curl -s -o /dev/null -w "%{http_code}" "$DEVUI_URL" 2>/dev/null | grep -qE "^(200|302)$"; then
        echo "[3/3] Quarkus Dev-UI is ready (${WAITED}s)"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "[3/3] Still waiting for Quarkus Dev-UI... (${WAITED}s/${MAX_WAIT}s)"
    fi
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "[3/3] ERROR: Quarkus Dev-UI did not become ready within ${MAX_WAIT}s"
    echo "Last 50 lines of log:"
    tail -50 "$TARGET_DIR/quarkus-dev.log"
    exit 1
fi

echo "=== E2E Dev-UI Test Environment Ready ==="
echo "  Keycloak:    https://localhost:1443"
echo "  Quarkus:     http://localhost:8080"
echo "  Dev-UI:      http://localhost:8080/q/dev-ui/"
echo "  Quarkus PID: $QUARKUS_PID"
