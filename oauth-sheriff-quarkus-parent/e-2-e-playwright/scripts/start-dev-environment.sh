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

# Build a merged truststore: JVM default CAs + localhost self-signed cert.
# The cui-http library uses java.net.http.HttpClient which relies on the JVM truststore,
# not the Quarkus TLS registry. We must provide a truststore that includes both
# public CA certs (for Maven Central) and the localhost cert (for Keycloak).
LOCALHOST_CERT="$INTEGRATION_TESTS_DIR/src/main/docker/certificates/localhost.crt"
MERGED_TRUSTSTORE="$TARGET_DIR/merged-truststore.p12"
if [ -n "${JAVA_HOME:-}" ]; then
    JAVA_CACERTS="$JAVA_HOME/lib/security/cacerts"
else
    JAVA_CACERTS="$(java -XshowSettings:property -version 2>&1 | grep 'java.home' | awk '{print $3}')/lib/security/cacerts"
fi

echo "[2/3] Building merged truststore..."
cp "$JAVA_CACERTS" "$MERGED_TRUSTSTORE"
chmod u+w "$MERGED_TRUSTSTORE"
keytool -importcert -trustcacerts -noprompt \
    -keystore "$MERGED_TRUSTSTORE" \
    -storepass changeit \
    -alias localhost-e2e \
    -file "$LOCALHOST_CERT" 2>/dev/null || echo "[2/3] Warning: keytool import returned non-zero (cert may already exist)"

# Start Quarkus dev mode in the background
# - enforceBuildGoal=false: integration-tests module disables the build goal by default
# - console.enabled=false: prevent interactive console from reading stdin in CI
# - log.console.color=false: clean log output without ANSI codes
# - javax.net.ssl.trustStore: merged truststore with CAs + localhost cert
MAVEN_OPTS="-Djavax.net.ssl.trustStore=$MERGED_TRUSTSTORE -Djavax.net.ssl.trustStorePassword=changeit" \
"$PROJECT_ROOT/mvnw" quarkus:dev \
    -Dquarkus.enforceBuildGoal=false \
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
# Use 127.0.0.1 instead of localhost to avoid IPv6 resolution issues in CI
DEVUI_URL="http://127.0.0.1:8080/q/dev-ui/"
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

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DEVUI_URL" 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE "^(200|301|302|303)$"; then
        echo "[3/3] Quarkus Dev-UI is ready (${WAITED}s, HTTP $HTTP_CODE)"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "[3/3] Still waiting for Quarkus Dev-UI... (${WAITED}s/${MAX_WAIT}s, last HTTP=$HTTP_CODE)"
    fi
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "[3/3] ERROR: Quarkus Dev-UI did not become ready within ${MAX_WAIT}s"
    echo "[3/3] Last HTTP code: $HTTP_CODE"
    echo "Last 50 lines of log:"
    tail -50 "$TARGET_DIR/quarkus-dev.log"
    exit 1
fi

# Verify Keycloak well-known endpoint returns correct URLs
echo "[3/3] Verifying Keycloak well-known endpoint..."
WELL_KNOWN=$(curl -sk "https://localhost:1443/realms/benchmark/.well-known/openid-configuration" 2>/dev/null || echo "FAILED")
echo "[3/3] Well-known issuer: $(echo "$WELL_KNOWN" | grep -o '"issuer":"[^"]*"' || echo 'N/A')"

echo "=== E2E Dev-UI Test Environment Ready ==="
echo "  Keycloak:    https://localhost:1443"
echo "  Quarkus:     http://127.0.0.1:8080"
echo "  Dev-UI:      http://127.0.0.1:8080/q/dev-ui/"
echo "  Quarkus PID: $QUARKUS_PID"
