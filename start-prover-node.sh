#!/bin/bash
# Production Prover Node Launcher
# Starts a complete prover node with all features enabled

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║     🌳 TRUSTLESS FRACTAL PROVER NETWORK 🌳               ║"
echo "║                                                           ║"
echo "║     φ-Optimized • Permissionless • CPU-Only              ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Configuration
DATA_DIR="${DATA_DIR:-./prover-data}"
LISTEN_ADDR="${LISTEN_ADDR:-/ip4/0.0.0.0/tcp/9000}"
BOOTSTRAP_PEERS="${BOOTSTRAP_PEERS:-}"
ETH_RPC_URL="${ETH_RPC_URL:-https://eth.llamarpc.com}"
STAKE_AMOUNT="${STAKE_AMOUNT:-1000}"
NODE_NAME="${NODE_NAME:-prover-$(hostname)}"

echo -e "${GREEN}📋 Configuration:${NC}"
echo "   Data Directory:    $DATA_DIR"
echo "   Listen Address:    $LISTEN_ADDR"
echo "   ETH RPC:          $ETH_RPC_URL"
echo "   Stake Amount:      $STAKE_AMOUNT FRAC"
echo "   Node Name:         $NODE_NAME"
echo ""

# Create data directory
mkdir -p "$DATA_DIR"
echo -e "${GREEN}✅ Created data directory${NC}"

# Check if server is built
if [ ! -f "./target/release/trustless-proving-server" ]; then
    echo -e "${YELLOW}⚠️  Server not built. Building now...${NC}"
    cargo build --release --bin trustless-proving-server
    echo -e "${GREEN}✅ Build complete${NC}"
fi

# Generate or load identity
echo ""
echo -e "${BLUE}🔑 Node Identity${NC}"
if [ -f "$DATA_DIR/node_identity.json" ]; then
    echo "   ✅ Existing identity found"
    PROVER_ID=$(cat "$DATA_DIR/node_identity.json" | grep -o '"public_key":\s*"\[.*\]"' | head -1)
    echo "   ID: $PROVER_ID"
else
    echo "   🆕 Generating new identity..."
    echo "   (This will create a new keypair)"
fi

echo ""
echo -e "${BLUE}🌐 Network Setup${NC}"
echo "   φ-optimized fractal topology"
echo "   Permissionless joining"
echo "   P2P task discovery"
echo ""

# Export environment variables
export RUST_LOG=info
export ENABLE_FRACTAL=true
export NODE_NAME="$NODE_NAME"
export DATA_DIR="$DATA_DIR"
export LISTEN_ADDR="$LISTEN_ADDR"
export BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS"
export ETH_RPC_URL="$ETH_RPC_URL"
export STAKE_AMOUNT="$STAKE_AMOUNT"

# Start the server
echo -e "${GREEN}🚀 Starting Prover Node...${NC}"
echo ""

# Run with signal handling
trap 'echo -e "\n${YELLOW}⚠️  Shutting down gracefully...${NC}"; kill $SERVER_PID 2>/dev/null; exit' INT TERM

./target/release/trustless-proving-server &
SERVER_PID=$!

# Wait a bit and check if it's running
sleep 2

if kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${GREEN}✅ Prover node is running (PID: $SERVER_PID)${NC}"
    echo ""
    echo -e "${BLUE}📊 Endpoints:${NC}"
    echo "   Health:     http://localhost:3000/health"
    echo "   Metrics:    http://localhost:3000/metrics"
    echo "   Prove API:  http://localhost:3000/api/prove"
    echo ""
    echo -e "${YELLOW}💡 Press Ctrl+C to stop${NC}"
    echo ""
    
    # Show live logs
    wait $SERVER_PID
else
    echo -e "${RED}❌ Failed to start server${NC}"
    exit 1
fi
