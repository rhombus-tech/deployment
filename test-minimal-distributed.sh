#!/bin/bash
# Minimal test to find the hang

set -e

echo "🔍 Minimal Distributed Test"
echo "==========================="
echo ""

pkill -9 trustless-proving-server 2>/dev/null || true
sleep 1

echo "Starting single node..."
PORT=8081 ./target/release/trustless-proving-server > /tmp/node1.log 2>&1 &
NODE1_PID=$!
sleep 3

echo "Node started: $NODE1_PID"
echo ""

echo "Test 1: Basic health check"
curl -s http://localhost:8081/health || echo "Health check failed"
echo ""

echo "Test 2: Make node1 leader (local operation)"
LEADER=$(curl -s -X POST http://localhost:8081/coordinator/leader/nominate \
  -H "Content-Type: application/json" \
  -d '{"node_id":"node1","address":"http://localhost:8081"}')
echo "Leader nomination result: $LEADER"
echo ""

echo "Test 3: Add task (local operation - node is leader)"
echo "Adding task..."
TASK_RESULT=$(timeout 5 curl -s -X POST http://localhost:8081/coordinator/tasks/add \
  -H "Content-Type: application/json" \
  -d '{"task_id":"test1","task_data":[1,2,3],"priority":"normal"}' || echo "TIMEOUT")
echo "Task add result: $TASK_RESULT"
echo ""

echo "Test 4: Get stats"
STATS=$(curl -s http://localhost:8081/coordinator/stats)
echo "Stats: $STATS"
echo ""

echo "Cleaning up..."
kill $NODE1_PID 2>/dev/null
sleep 1
pkill -9 trustless-proving-server 2>/dev/null || true

echo "✅ Minimal test complete"
