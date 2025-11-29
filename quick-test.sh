#!/bin/bash
# Quick verification that everything works
set -e

echo "🧪 QUICK SYSTEM TEST"
echo "══════════════════════"
echo ""

# Kill any existing server
pkill -9 trustless-proving-server 2>/dev/null || true
sleep 1

# Check if server binary exists
if [ ! -f "target/release/trustless-proving-server" ]; then
    echo "❌ Server not built. Run: cargo build --release"
    exit 1
fi

# Start server
echo "🚀 Starting server..."
ENABLE_FRACTAL=true RUST_LOG=info ./target/release/trustless-proving-server > /tmp/test-server.log 2>&1 &
SERVER_PID=$!
echo "   PID: $SERVER_PID"

# Wait for startup
echo "⏳ Waiting for server..."
sleep 3

# Test health
echo -n "📡 Testing /health... "
if curl -sf http://localhost:3000/health > /dev/null; then
    echo "✅"
else
    echo "❌ FAILED"
    cat /tmp/test-server.log
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test metrics
echo -n "📊 Testing /metrics... "
if curl -sf http://localhost:3000/metrics > /dev/null; then
    echo "✅"
else
    echo "❌ FAILED"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test proving
echo -n "⚡ Testing proof generation... "
RESPONSE=$(curl -sf -X POST http://localhost:3000/api/prove \
  -H "Content-Type: application/json" \
  -d '{"to":"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb","data":"0x","value":"0","gas_limit":"21000"}' 2>/dev/null)

if [ -n "$RESPONSE" ]; then
    SIZE=$(echo "$RESPONSE" | grep -o '"proof_size_bytes":[0-9]*' | cut -d: -f2)
    if [ "$SIZE" = "8192" ]; then
        echo "✅ (8KB proof)"
    else
        echo "❌ Wrong size: $SIZE"
        kill $SERVER_PID 2>/dev/null
        exit 1
    fi
else
    echo "❌ FAILED"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test batch
echo -n "📦 Testing batch proving... "
BATCH=$(curl -sf -X POST http://localhost:3000/api/batch-prove \
  -H "Content-Type: application/json" \
  -d '{"transactions":[{"to":"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb","data":"0x","value":"0","gas_limit":"21000"},{"to":"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb","data":"0x","value":"0","gas_limit":"21000"}]}' 2>/dev/null)

if [ -n "$BATCH" ]; then
    echo "✅"
else
    echo "❌ FAILED"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Cleanup
kill $SERVER_PID 2>/dev/null

echo ""
echo "══════════════════════"
echo "✅ ALL TESTS PASSED"
echo ""
echo "System is working! 🎉"
echo ""
echo "Next steps:"
echo "  • make docker         # Build Docker image"
echo "  • make deploy-local   # Test locally with docker-compose"
echo "  • make deploy-staging # Deploy to staging"
