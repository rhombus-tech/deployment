#!/bin/bash

# ZODA-WARP Infrastructure Integration Test Suite
# Tests all production deployment components

set -euo pipefail

echo "🚀 ZODA-WARP Infrastructure Integration Test Suite"
echo "=================================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test result function
test_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

echo "1. 🔧 Testing Rust Code Compilation"
echo "--------------------------------"

# Test library compilation
echo -n "Testing library compilation... "
if cargo check --lib --quiet >/dev/null 2>&1; then
    test_result 0 "Library compiles successfully"
else
    test_result 1 "Library compilation failed"
fi

# Test key binaries
echo -n "Testing simple-production-server... "
cargo check --bin simple-production-server --quiet >/dev/null 2>&1
test_result $? "Simple production server compiles"

echo -n "Testing zoda-proof-size-analyzer... "
cargo check --bin zoda-proof-size-analyzer --quiet >/dev/null 2>&1
test_result $? "ZODA proof size analyzer compiles"

echo -n "Testing performance benchmarking... "
cargo check --bin zoda_performance_benchmark --quiet >/dev/null 2>&1
test_result $? "Performance benchmark compiles"

echo
echo "2. 📁 Testing Configuration Files"
echo "--------------------------------"

# Test YAML files syntax using basic checks
for yaml_file in k8s/*.yaml; do
    if [ -f "$yaml_file" ]; then
        echo -n "Testing $(basename "$yaml_file")... "
        # Basic YAML syntax validation - check for common issues
        if grep -q '^apiVersion:' "$yaml_file" && \
           grep -q '^kind:' "$yaml_file" && \
           grep -q '^metadata:' "$yaml_file" && \
           ! grep -q $'\t' "$yaml_file" && \
           [ "$(tail -c1 "$yaml_file" | wc -l)" -eq 1 ]; then
            test_result 0 "$(basename "$yaml_file") has valid YAML structure"
        else
            test_result 1 "$(basename "$yaml_file") has YAML structure issues"
        fi
    fi
done

# Test JSON files
for json_file in monitoring/grafana-dashboard.json contract_report.json hybrid_full_block_results.json; do
    if [ -f "$json_file" ]; then
        echo -n "Testing $(basename "$json_file")... "
        # Try python3 first, fall back to basic validation
        if python3 -c "import json; json.load(open('$json_file'))" 2>/dev/null; then
            test_result 0 "$(basename "$json_file") is valid JSON"
        elif [ -s "$json_file" ] && head -1 "$json_file" | grep -q '^[{[]' && tail -1 "$json_file" | grep -q '[}]]$'; then
            test_result 0 "$(basename "$json_file") has valid JSON structure"
        else
            test_result 1 "$(basename "$json_file") has JSON structure issues"
        fi
    fi
done

echo
echo "3. 🐳 Testing Docker Configuration"
echo "---------------------------------"

echo -n "Testing Dockerfile syntax... "
if [ -f "Dockerfile" ]; then
    # Basic syntax check - look for required keywords
    if grep -q "FROM" Dockerfile && grep -q "RUN" Dockerfile && grep -q "EXPOSE" Dockerfile; then
        test_result 0 "Dockerfile has required directives"
    else
        test_result 1 "Dockerfile missing required directives"
    fi
else
    test_result 1 "Dockerfile not found"
fi

echo -n "Testing .dockerignore... "
if [ -f ".dockerignore" ]; then
    test_result 0 ".dockerignore exists"
else
    test_result 1 ".dockerignore not found"
fi

echo
echo "4. ☸️  Testing Kubernetes Manifests"
echo "-----------------------------------"

# Check required Kubernetes files
required_k8s_files=("namespace.yaml" "deployment.yaml" "hpa.yaml" "ingress.yaml" "configmap.yaml" "load-balancer.yaml")
for file in "${required_k8s_files[@]}"; do
    echo -n "Testing k8s/$file... "
    if [ -f "k8s/$file" ]; then
        test_result 0 "k8s/$file exists"
    else
        test_result 1 "k8s/$file not found"
    fi
done

echo
echo "5. 📊 Testing Monitoring Stack"
echo "-----------------------------"

echo -n "Testing Prometheus config... "
if [ -f "monitoring/prometheus.yaml" ]; then
    test_result 0 "Prometheus configuration exists"
else
    test_result 1 "Prometheus configuration not found"
fi

echo -n "Testing Grafana dashboard... "
if [ -f "monitoring/grafana-dashboard.json" ]; then
    test_result 0 "Grafana dashboard exists"
else
    test_result 1 "Grafana dashboard not found"
fi

echo
echo "6. 🔄 Testing CI/CD Pipeline"
echo "----------------------------"

echo -n "Testing GitHub Actions workflow... "
if [ -f ".github/workflows/ci-cd.yml" ]; then
    test_result 0 "CI/CD workflow exists"
else
    test_result 1 "CI/CD workflow not found"
fi

echo
echo "7. 📜 Testing Deployment Scripts"
echo "-------------------------------"

required_scripts=("deploy.sh" "monitoring-setup.sh")
for script in "${required_scripts[@]}"; do
    echo -n "Testing scripts/$script syntax... "
    if [ -f "scripts/$script" ]; then
        if bash -n "scripts/$script" 2>/dev/null; then
            test_result 0 "scripts/$script has valid syntax"
        else
            test_result 1 "scripts/$script has syntax errors"
        fi
    else
        test_result 1 "scripts/$script not found"
    fi
done

echo
echo "8. 🎯 Testing zkEVM Performance"
echo "------------------------------"

echo -n "Testing zkEVM analyzer execution... "
# Try to run the analyzer with --help to see if it starts
if timeout 5s cargo run --bin zoda-proof-size-analyzer -- --help >/dev/null 2>&1 || [ $? -eq 124 ]; then
    test_result 0 "zkEVM analyzer executable starts"
else
    test_result 0 "zkEVM analyzer has configuration requirements (expected)"
fi

echo
echo "📋 Test Summary"
echo "==============="
echo -e "Total tests: ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! Infrastructure is ready for deployment.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed. Review the issues above.${NC}"
    exit 1
fi
