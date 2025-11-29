#!/bin/bash
# FRAC RPC Production Deployment Script
# Sets up complete RPC infrastructure for zkEVM proving

set -e

echo "🚀 FRAC RPC Production Deployment"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "⚠️  Please don't run as root"
   exit 1
fi

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose found"
echo ""

# Create necessary directories
echo "📁 Creating data directories..."
mkdir -p data/erigon-primary
mkdir -p data/erigon-secondary
mkdir -p data/geth
mkdir -p data/redis
mkdir -p data/postgres
mkdir -p data/prometheus
mkdir -p data/grafana
mkdir -p logs
echo "✅ Data directories created"
echo ""

# Check if .env.production exists
if [ ! -f .env.production ]; then
    echo "❌ .env.production not found!"
    echo "Please create .env.production with your configuration"
    exit 1
fi

# Copy production env to .env
cp .env.production .env
echo "✅ Production configuration loaded"
echo ""

# Check for API keys
if grep -q "YOUR_ALCHEMY_KEY_HERE" .env; then
    echo "⚠️  WARNING: Alchemy API key not set in .env.production"
    echo "   Continuing without Alchemy fallback..."
fi

if grep -q "YOUR_INFURA_KEY_HERE" .env; then
    echo "⚠️  WARNING: Infura API key not set in .env.production"
    echo "   Continuing without Infura fallback..."
fi

echo ""
echo "📋 Deployment Summary:"
echo "   - Primary RPC: erigon-primary:8545"
echo "   - Secondary RPC: erigon-secondary:8545"
echo "   - Redis Cache: redis:6379"
echo "   - PostgreSQL: postgres:5432"
echo "   - FRAC RPC Gateway: 0.0.0.0:8545"
echo "   - Metrics: 0.0.0.0:9090"
echo ""

read -p "🤔 Deploy FRAC RPC infrastructure? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 0
fi

echo ""
echo "🔨 Building FRAC RPC..."
docker-compose build frac-rpc

echo ""
echo "🚀 Starting infrastructure..."
echo ""

# Start in stages to ensure dependencies are ready
echo "📦 Stage 1: Starting cache layer (Redis + PostgreSQL)..."
docker-compose up -d redis postgres
sleep 5

echo "📦 Stage 2: Starting Ethereum nodes..."
docker-compose up -d erigon-primary erigon-secondary geth
sleep 10

echo "📦 Stage 3: Starting FRAC RPC Gateway..."
docker-compose up -d frac-rpc

echo "📦 Stage 4: Starting monitoring..."
docker-compose up -d prometheus grafana

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

echo ""
echo "🔍 Checking service status..."
docker-compose ps

echo ""
echo "✅ FRAC RPC Production Deployment Complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Service Endpoints:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   RPC Endpoint:     http://localhost:8545"
echo "   WebSocket:        ws://localhost:8545/ws"
echo "   Health Check:     http://localhost:8545/health"
echo "   Metrics:          http://localhost:8545/metrics"
echo "   Stats:            http://localhost:8545/stats"
echo "   Prometheus:       http://localhost:9091"
echo "   Grafana:          http://localhost:3000"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 Proving Endpoints:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   Single Block:     GET  http://localhost:8545/v1/proving/block/{number}"
echo "   Batch Blocks:     POST http://localhost:8545/v1/proving/batch"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 Quick Test:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   curl http://localhost:8545/health"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚠️  Important Notes:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   1. Erigon nodes will take 3-7 days to sync initially"
echo "   2. During sync, external fallbacks (Alchemy/Infura) will be used"
echo "   3. Once synced, 90%+ traffic will use YOUR nodes"
echo "   4. Monitor logs: docker-compose logs -f frac-rpc"
echo "   5. Check node sync: docker-compose logs -f erigon-primary"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔧 Management Commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   View logs:        docker-compose logs -f frac-rpc"
echo "   Restart:          docker-compose restart frac-rpc"
echo "   Stop all:         docker-compose down"
echo "   Stop (keep data): docker-compose stop"
echo "   View stats:       curl http://localhost:8545/stats | jq"
echo ""
echo "🎉 Happy Proving!"
