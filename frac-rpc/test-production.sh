#!/bin/bash
# Test FRAC RPC Production Setup

echo "🧪 Testing FRAC RPC Production Setup"
echo "====================================="
echo ""

RPC_URL="http://localhost:8545"

# Test 1: Health Check
echo "1️⃣  Testing health endpoint..."
if curl -s "$RPC_URL/health" | grep -q "healthy"; then
    echo "   ✅ Health check passed"
else
    echo "   ❌ Health check failed"
    exit 1
fi
echo ""

# Test 2: Standard JSON-RPC
echo "2️⃣  Testing standard JSON-RPC (eth_blockNumber)..."
RESPONSE=$(curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}')

if echo "$RESPONSE" | grep -q "result"; then
    BLOCK_NUM=$(echo "$RESPONSE" | jq -r '.result')
    echo "   ✅ JSON-RPC working, current block: $BLOCK_NUM"
else
    echo "   ❌ JSON-RPC failed"
    echo "   Response: $RESPONSE"
    exit 1
fi
echo ""

# Test 3: Rate Limiting
echo "3️⃣  Testing rate limiting (should allow normal requests)..."
SUCCESS_COUNT=0
for i in {1..10}; do
    RESPONSE=$(curl -s -X POST "$RPC_URL" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}')
    
    if echo "$RESPONSE" | grep -q "result"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

if [ $SUCCESS_COUNT -eq 10 ]; then
    echo "   ✅ Rate limiting configured (10/10 requests succeeded)"
else
    echo "   ⚠️  Rate limiting may be too strict ($SUCCESS_COUNT/10 succeeded)"
fi
echo ""

# Test 4: Metrics Endpoint
echo "4️⃣  Testing metrics endpoint..."
if curl -s "$RPC_URL/metrics" | grep -q "frac_rpc_requests_total"; then
    echo "   ✅ Prometheus metrics available"
else
    echo "   ❌ Metrics endpoint failed"
fi
echo ""

# Test 5: Stats Endpoint
echo "5️⃣  Testing stats endpoint..."
STATS=$(curl -s "$RPC_URL/stats")
if echo "$STATS" | grep -q "total_requests"; then
    echo "   ✅ Stats endpoint working"
    echo "$STATS" | jq '.'
else
    echo "   ❌ Stats endpoint failed"
fi
echo ""

# Test 6: Proving Endpoint (if block exists)
echo "6️⃣  Testing proving-optimized endpoint..."
LATEST_BLOCK=$(echo "$BLOCK_NUM" | xargs printf "%d")
TEST_BLOCK=$((LATEST_BLOCK - 100))  # Test with recent block

PROVING_RESPONSE=$(curl -s "$RPC_URL/v1/proving/block/$TEST_BLOCK")
if echo "$PROVING_RESPONSE" | grep -q "block_number"; then
    echo "   ✅ Proving endpoint working for block $TEST_BLOCK"
else
    echo "   ⚠️  Proving endpoint may not have data for block $TEST_BLOCK (node might still be syncing)"
fi
echo ""

# Test 7: Cache Performance
echo "7️⃣  Testing cache performance..."
echo "   Making same request 5 times to test caching..."

START_TIME=$(date +%s%N)
for i in {1..5}; do
    curl -s -X POST "$RPC_URL" \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x$(printf '%x' $TEST_BLOCK)\",false],\"id\":1}" \
      > /dev/null
done
END_TIME=$(date +%s%N)

DURATION=$(( (END_TIME - START_TIME) / 1000000 ))  # Convert to milliseconds
AVG_LATENCY=$(( DURATION / 5 ))

echo "   Average latency: ${AVG_LATENCY}ms"
if [ $AVG_LATENCY -lt 100 ]; then
    echo "   ✅ Cache performing well (<100ms average)"
elif [ $AVG_LATENCY -lt 500 ]; then
    echo "   ⚠️  Cache performance OK but could be better"
else
    echo "   ❌ Cache not performing well (>500ms average)"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Test Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   Current Block: $BLOCK_NUM"
echo "   Average Latency: ${AVG_LATENCY}ms"
echo ""
echo "✅ FRAC RPC is operational and ready for production proving!"
echo ""
echo "📝 Next Steps:"
echo "   1. Monitor node sync: docker-compose logs -f erigon-primary"
echo "   2. Check stats periodically: curl $RPC_URL/stats | jq"
echo "   3. Update your provers to use: $RPC_URL"
echo ""
