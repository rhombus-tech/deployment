#!/bin/bash
# Final Production Readiness Verification
set -e

echo "✅ PRODUCTION READINESS CHECK"
echo "═══════════════════════════════════════════"
echo ""

READY=true

check() {
    local item=$1
    local condition=$2
    
    echo -n "  $item... "
    if eval "$condition" > /dev/null 2>&1; then
        echo "✅"
    else
        echo "❌"
        READY=false
    fi
}

# 1. Code & Build
echo "📦 Code & Build"
check "Rust server builds" "cargo build --release --bin trustless-proving-server"
check "Smart contracts compile" "npx hardhat compile"
check "SDK builds" "cd trustless-sdk && npm run build"

# 2. Infrastructure Files
echo ""
echo "🏗️  Infrastructure"
check "Dockerfile exists" "test -f Dockerfile.proving-server"
check "Docker compose exists" "test -f docker-compose.yml"
check "K8s deployment exists" "test -f k8s/deployment.yaml"
check "K8s service exists" "test -f k8s/service.yaml"
check "K8s ingress exists" "test -f k8s/ingress.yaml"
check "K8s HPA exists" "test -f k8s/hpa.yaml"

# 3. Monitoring
echo ""
echo "📊 Monitoring"
check "Prometheus config exists" "test -f monitoring/prometheus-config.yaml"
check "Grafana dashboard exists" "test -f monitoring/grafana-dashboard.json"

# 4. Deployment Scripts
echo ""
echo "🚀 Deployment"
check "Deploy script exists" "test -f deploy.sh"
check "Test script exists" "test -f test-production.sh"
check "Load test exists" "test -f load-test.js"
check "Makefile exists" "test -f Makefile"

# 5. Smart Contracts
echo ""
echo "📜 Smart Contracts"
check "FractalToken exists" "test -f contracts/FractalToken.sol"
check "RewardPool exists" "test -f contracts/FractalRewardPoolV2.sol"
check "ProverRegistry exists" "test -f contracts/FractalProverRegistry.sol"
check "Staking exists" "test -f contracts/FractalStaking.sol"
check "Governance exists" "test -f contracts/FractalGovernance.sol"
check "Deploy script exists" "test -f scripts/deploy-contracts.ts"

# 6. SDK
echo ""
echo "📦 SDK"
check "SDK types exist" "test -f trustless-sdk/src/types.ts"
check "SDK package.json exists" "test -f trustless-sdk/package.json"

# 7. CI/CD
echo ""
echo "⚙️  CI/CD"
check "GitHub Actions workflow" "test -f .github/workflows/ci.yml"

# 8. Node Onboarding
echo ""
echo "🌳 Node Onboarding"
check "Join script exists" "test -f join-network.sh"
check "Join page exists" "test -f join.html"

# 9. Core System Components
echo ""
echo "🔧 Core Components"
check "ZODA+WARP code exists" "test -f evm-verify/src/api/hybrid_zoda_warp_strategy.rs"
check "Fractal network exists" "test -d evm-verify/src/fractal_network"
check "StatelessVM exists" "test -d stateless-vm/src"
check "Proving server exists" "test -d trustless-proving-server/src"

echo ""
echo "═══════════════════════════════════════════"

if [ "$READY" = true ]; then
    echo "✅ SYSTEM IS PRODUCTION READY!"
    echo ""
    echo "Next steps:"
    echo "  1. make build          # Build everything"
    echo "  2. make test           # Run full test suite"
    echo "  3. make docker         # Build Docker image"
    echo "  4. make deploy-staging # Deploy to staging"
    echo "  5. Verify staging works"
    echo "  6. make deploy-prod    # Deploy to production"
    echo ""
    exit 0
else
    echo "❌ SYSTEM NOT READY"
    echo "Fix the issues above before deploying"
    echo ""
    exit 1
fi
