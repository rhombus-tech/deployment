#!/bin/bash
# One-command production deployment
set -e

echo "🚀 TRUSTLESS NETWORK DEPLOYMENT"
echo "═══════════════════════════════════"
echo ""

# Check environment
if [ -z "$DEPLOY_ENV" ]; then
    echo "❌ Error: DEPLOY_ENV not set (production/staging)"
    exit 1
fi

echo "📍 Environment: $DEPLOY_ENV"
echo ""

# Build everything
echo "🔨 Building..."
echo "─────────────────"

# Build Rust
echo "  → Rust server..."
cargo build --release --bin trustless-proving-server

# Build contracts
echo "  → Smart contracts..."
npx hardhat compile

# Build SDK
echo "  → TypeScript SDK..."
cd trustless-sdk && npm run build && cd ..

echo "✅ Build complete"
echo ""

# Docker
echo "🐳 Building Docker image..."
docker build -f Dockerfile.proving-server -t trustless/proving-server:latest .
docker tag trustless/proving-server:latest trustless/proving-server:$(git rev-parse --short HEAD)

if [ "$DEPLOY_ENV" = "production" ]; then
    echo "  → Pushing to registry..."
    docker push trustless/proving-server:latest
    docker push trustless/proving-server:$(git rev-parse --short HEAD)
fi

echo "✅ Docker complete"
echo ""

# Kubernetes
if command -v kubectl &> /dev/null; then
    echo "☸️  Deploying to Kubernetes..."
    
    NAMESPACE="trustless-$DEPLOY_ENV"
    
    # Apply configs
    kubectl apply -f k8s/configmap.yaml -n $NAMESPACE
    kubectl apply -f k8s/deployment.yaml -n $NAMESPACE
    kubectl apply -f k8s/service.yaml -n $NAMESPACE
    kubectl apply -f k8s/ingress.yaml -n $NAMESPACE
    kubectl apply -f k8s/hpa.yaml -n $NAMESPACE
    
    # Wait for rollout
    echo "  → Waiting for rollout..."
    kubectl rollout status deployment/trustless-proving-server -n $NAMESPACE --timeout=5m
    
    echo "✅ Kubernetes deployment complete"
else
    echo "⚠️  kubectl not found, skipping K8s deployment"
    echo "  → Using docker-compose instead..."
    docker-compose up -d
    echo "✅ Docker Compose deployment complete"
fi

echo ""
echo "═══════════════════════════════════"
echo "✅ DEPLOYMENT COMPLETE"
echo ""
echo "🔗 Endpoints:"
if [ "$DEPLOY_ENV" = "production" ]; then
    echo "   API: https://prover.trustless.network"
    echo "   Metrics: https://prover.trustless.network/metrics"
else
    echo "   API: https://staging.prover.trustless.network"
    echo "   Metrics: https://staging.prover.trustless.network/metrics"
fi
echo ""
echo "📊 Monitor at: https://grafana.trustless.network"
echo "═══════════════════════════════════"
