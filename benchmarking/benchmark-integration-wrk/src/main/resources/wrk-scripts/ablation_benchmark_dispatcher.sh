#!/bin/bash
# Ablation Benchmark Dispatcher
# Runs all ablation benchmark variants sequentially in a single Maven execution
# This avoids duplicating exec-maven-plugin configuration for each variant
# Pattern follows jfr_benchmark_dispatcher.sh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=== Ablation Benchmark Dispatcher ==="
echo "Running all ablation variants sequentially..."
echo ""

FAILED=0

for script in mock_jwt_benchmark.sh direct_validation_benchmark.sh ablation_baseline_benchmark.sh ablation_header_only_benchmark.sh; do
    echo "--- Running: $script ---"
    if bash "$SCRIPT_DIR/$script"; then
        echo "--- Completed: $script ---"
    else
        echo "--- FAILED: $script ---"
        FAILED=1
    fi
    echo ""
done

if [ "$FAILED" -ne 0 ]; then
    echo "=== Ablation Dispatcher: Some benchmarks FAILED ==="
    exit 1
fi

echo "=== Ablation Dispatcher: All benchmarks completed successfully ==="
