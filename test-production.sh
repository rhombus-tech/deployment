#!/bin/bash
# Production System Test - Verify Everything Works
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🧪 TRUSTLESS PRODUCTION SYSTEM TEST"
echo "═══════════════════════════════════"
echo ""

ERRORS=0

# Test function
test_component() {
    local name=$1
    local command=$2
    
    echo -n "Testing $name... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        ((ERRORS++))
    fi
}

# 1. Build Tests
echo "📦 BUILD TESTS"
echo "─────────────────"

test_component "Rust proving server" "cd trustless-proving-server && cargo build --release"
test_component "EVM verify library" "cd evm-verify && cargo build --release"
test_component "Stateless VM" "cd stateless-vm && cargo build --release"
test_component "Smart contracts" "npx hardhat compile"
test_component "TypeScript SDK" "cd trustless-sdk && npm run build"

echo ""

# 2. Server Tests
echo "🖥️  SERVER TESTS"
echo "─────────────────"

# Start server in background
echo "Starting server..."
ENABLE_FRACTAL=true ./target/release/trustless-proving-server > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 3

test_component "Server health endpoint" "curl -sf http://localhost:3000/health"
test_component "Metrics endpoint" "curl -sf http://localhost:3000/metrics"

# Test proving
echo -n "Testing proof generation... "
PROOF_RESPONSE=$(curl -sf -X POST http://localhost:3000/api/prove \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "data": "0x",
    "value": "0",
    "gas_limit": "21000"
  }' 2>/dev/null)

if [ -n "$PROOF_RESPONSE" ]; then
    PROOF_SIZE=$(echo $PROOF_RESPONSE | jq -r '.proof_size_bytes' 2>/dev/null)
    if [ "$PROOF_SIZE" = "8192" ]; then
        echo -e "${GREEN}✓${NC} (8KB proof)"
    else
        echo -e "${RED}✗${NC} (wrong size: $PROOF_SIZE)"
        ((ERRORS++))
    fi
else
    echo -e "${RED}✗${NC}"
    ((ERRORS++))
fi

# Test batch proving
echo -n "Testing batch proving... "
BATCH_RESPONSE=$(curl -sf -X POST http://localhost:3000/api/batch-prove \
  -H "Content-Type: application/json" \
  -d '{
    "transactions": [
      {"to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb", "data": "0x", "value": "0", "gas_limit": "21000"},
      {"to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb", "data": "0x", "value": "0", "gas_limit": "21000"}
    ]
  }' 2>/dev/null)

if [ -n "$BATCH_RESPONSE" ]; then
    BATCH_SIZE=$(echo $BATCH_RESPONSE | jq -r '.batch_size' 2>/dev/null)
    if [ "$BATCH_SIZE" = "2" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        ((ERRORS++))
    fi
else
    echo -e "${RED}✗${NC}"
    ((ERRORS++))
fi

# Cleanup server
kill $SERVER_PID 2>/dev/null || true
sleep 1

echo ""

# 3. Docker Tests
echo "🐳 DOCKER TESTS"
echo "─────────────────"

test_component "Docker build" "docker build -f Dockerfile.proving-server -t trustless-test ."
test_component "Docker compose syntax" "docker-compose config"

echo ""

# 4. Kubernetes Tests
echo "☸️  KUBERNETES TESTS"
echo "─────────────────"

test_component "K8s deployment yaml" "kubectl apply --dry-run=client -f k8s/deployment.yaml"
test_component "K8s service yaml" "kubectl apply --dry-run=client -f k8s/service.yaml"
test_component "K8s ingress yaml" "kubectl apply --dry-run=client -f k8s/ingress.yaml"
test_component "K8s HPA yaml" "kubectl apply --dry-run=client -f k8s/hpa.yaml"

echo ""

# 5. Contract Tests
echo "📜 CONTRACT TESTS"
echo "─────────────────"

test_component "Contract compilation" "npx hardhat compile"
test_component "Contract tests" "npx hardhat test"

echo ""

# 6. Integration Test
echo "🔗 INTEGRATION TEST"
echo "─────────────────"

test_component "Full system test" "node test-complete-system.js"

echo ""

# Summary
echo "═══════════════════════════════════"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
    echo "System is ready for production!"
    exit 0
else
    echo -e "${RED}❌ $ERRORS TEST(S) FAILED${NC}"
    echo "Fix errors before deploying to production"
    exit 1
fi
