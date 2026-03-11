#!/bin/bash
# JFR Benchmark Dispatcher
# Routes to the correct benchmark script based on JFR_BENCHMARK environment variable
# Used by the benchmark-jfr Maven profile to run a single benchmark under JFR profiling

set -e

: "${JFR_BENCHMARK:?ERROR: JFR_BENCHMARK environment variable is not set}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "=== JFR Benchmark Dispatcher ==="
echo "Selected benchmark: $JFR_BENCHMARK"
echo ""

case "$JFR_BENCHMARK" in
    jwt)
        exec bash "$SCRIPT_DIR/jwt_benchmark.sh"
        ;;
    health)
        exec bash "$SCRIPT_DIR/health_live_benchmark.sh"
        ;;
    direct-validation)
        exec bash "$SCRIPT_DIR/direct_validation_benchmark.sh"
        ;;
    mock-jwt)
        exec bash "$SCRIPT_DIR/mock_jwt_benchmark.sh"
        ;;
    ablation-baseline)
        exec bash "$SCRIPT_DIR/ablation_baseline_benchmark.sh"
        ;;
    ablation-header-only)
        exec bash "$SCRIPT_DIR/ablation_header_only_benchmark.sh"
        ;;
    *)
        echo "ERROR: Unknown benchmark '$JFR_BENCHMARK'"
        echo "Supported values: jwt, health, direct-validation, mock-jwt, ablation-baseline, ablation-header-only"
        exit 1
        ;;
esac
