#!/bin/bash
# Test Multi-Node Prover Network

set -e

echo "🧹 Cleaning up old processes..."
pkill -9 trustless-proving-server 2>/dev/null || true
sleep 1

echo ""
echo "🚀 Starting 3-node network..."
echo ""

# Node 1 - Port 8081
echo "📡 Node 1: http://localhost:8081"
PORT=8081 ./target/release/trustless-proving-server > /tmp/node1.log 2>&1 &
NODE1_PID=$!
sleep 2

# Node 2 - Port 8082  
echo "📡 Node 2: http://localhost:8082"
PORT=8082 ./target/release/trustless-proving-server > /tmp/node2.log 2>&1 &
NODE2_PID=$!
sleep 2

# Node 3 - Port 8083
echo "📡 Node 3: http://localhost:8083"
PORT=8083 ./target/release/trustless-proving-server > /tmp/node3.log 2>&1 &
NODE3_PID=$!
sleep 2

echo ""
echo "✅ All nodes started!"
echo ""
echo "PIDs: $NODE1_PID, $NODE2_PID, $NODE3_PID"
echo ""

# Test each node
echo "🧪 Testing each node..."
echo ""

for port in 8081 8082 8083; do
    echo "Node on port $port:"
    health=$(curl -s http://localhost:$port/health 2>/dev/null || echo "FAILED")
    if echo "$health" | grep -q "healthy"; then
        node_id=$(echo "$health" | jq -r '.version' 2>/dev/null || echo "unknown")
        proofs=$(echo "$health" | jq -r '.total_proofs' 2>/dev/null || echo "0")
        echo "  ✅ Healthy (version: $node_id, proofs: $proofs)"
    else
        echo "  ❌ Failed to connect"
    fi
done

echo ""
echo "📊 Testing proof generation on Node 1..."
RESULT=$(curl -s -X POST http://localhost:8081/api/prove \
  -H "Content-Type: application/json" \
  -d '{"to":"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb","data":"0x","value":"0","gasLimit":"21000"}')

if echo "$RESULT" | grep -q "proof"; then
    PROOF_TIME=$(echo "$RESULT" | jq -r '.proving_time_ms')
    PROOF_SIZE=$(echo "$RESULT" | jq -r '.proof_size_bytes')
    echo "  ✅ Proof generated: ${PROOF_TIME}ms, ${PROOF_SIZE} bytes"
else
    echo "  ❌ Proof generation failed"
fi

echo ""
echo "🔗 Testing peer discovery..."
# Node 2 announces itself to Node 1
curl -s -X POST http://localhost:8081/network/announce \
  -H "Content-Type: application/json" \
  -d '{"node_id":"node_2","address":"http://localhost:8082"}' > /dev/null

# Node 3 announces itself to Node 1  
curl -s -X POST http://localhost:8081/network/announce \
  -H "Content-Type: application/json" \
  -d '{"node_id":"node_3","address":"http://localhost:8083"}' > /dev/null

# Check Node 1's peer list
PEERS=$(curl -s http://localhost:8081/network/peers | jq -r '.count')
if [ "$PEERS" -ge 2 ]; then
    echo "  ✅ Node 1 discovered $PEERS peers"
else
    echo "  ⚠️  Node 1 has $PEERS peers (expected 2+)"
fi

echo ""
echo "📡 Testing task distribution..."
TASK_RESP=$(curl -s -X POST http://localhost:8082/network/task \
  -H "Content-Type: application/json" \
  -d '{"task_id":"test-task-1","task_data":[1,2,3],"announced_by":"node_1"}')

if echo "$TASK_RESP" | grep -q "ok"; then
    echo "  ✅ Task distributed successfully"
else
    echo "  ❌ Task distribution failed"
fi

echo ""
echo "🎯 Multi-node network operational!"
echo ""
echo "To stop: kill $NODE1_PID $NODE2_PID $NODE3_PID"
echo "Logs: /tmp/node{1,2,3}.log"
echo ""
echo "Press Ctrl+C to shutdown..."

# Wait for Ctrl+C
trap "echo ''; echo '🛑 Shutting down...'; kill $NODE1_PID $NODE2_PID $NODE3_PID 2>/dev/null; exit" INT TERM
wait
