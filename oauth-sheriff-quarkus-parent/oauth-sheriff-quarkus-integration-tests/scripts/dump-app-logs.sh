#!/bin/bash

# Application Container Log Dumping Script
# Usage: ./dump-app-logs.sh <target-directory>
# Example: ./dump-app-logs.sh target

set -euo pipefail

# Configuration
APP_CONTAINER_NAME="oauth-sheriff-quarkus-integration-tests-oauth-sheriff-integration-tests-1"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
APP_LOG_FILENAME="app-logs-${TIMESTAMP}.txt"

# Parameter validation
if [ $# -ne 1 ]; then
    echo "❌ Error: Target directory parameter required"
    echo "Usage: $0 <target-directory>"
    exit 1
fi

TARGET_DIR="$1"

# Create target directory if it doesn't exist
if [ ! -d "$TARGET_DIR" ]; then
    mkdir -p "$TARGET_DIR"
fi

# Resolve absolute path
TARGET_ABS_PATH=$(cd "$TARGET_DIR" && pwd)
APP_LOG_FILE_PATH="${TARGET_ABS_PATH}/${APP_LOG_FILENAME}"

echo "🚀 Dumping application container logs..."
echo "📦 App container: $APP_CONTAINER_NAME"
echo "📝 Output file: $APP_LOG_FILE_PATH"

# Check if container exists
if ! docker ps -a --format "table {{.Names}}" | grep -q "^${APP_CONTAINER_NAME}$"; then
    echo "⚠️  Container $APP_CONTAINER_NAME not found, skipping log dump"
    exit 0
fi

# Dump logs
if docker logs "$APP_CONTAINER_NAME" > "$APP_LOG_FILE_PATH" 2>&1; then
    LOG_SIZE=$(wc -l < "$APP_LOG_FILE_PATH")
    FILE_SIZE=$(du -h "$APP_LOG_FILE_PATH" | cut -f1)
    echo "✅ Successfully dumped $LOG_SIZE lines ($FILE_SIZE)"
    echo "📍 Full path: $APP_LOG_FILE_PATH"

    # Echo JWE-related diagnostic lines to stdout for CI visibility
    echo ""
    echo "📋 JWE diagnostic lines from app container:"
    grep -i "jwe\|decryption" "$APP_LOG_FILE_PATH" || echo "  (no JWE-related log lines found)"
    echo ""
else
    echo "⚠️  Failed to dump logs from container: $APP_CONTAINER_NAME"
    exit 0
fi
