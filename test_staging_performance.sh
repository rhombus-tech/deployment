#!/bin/bash

# Performance test script for zkEVM staging environment
# Tests the performance improvements we implemented

echo "🎯 ZKVM STAGING PERFORMANCE TEST"
echo "================================="
echo "Testing endpoint: https://zk-evm.org"
echo "Test time: $(date)"
echo ""

# Test 1: Status endpoint response times
echo "🔍 Testing /status endpoint (10 requests)..."
echo ""

total_time=0
proving_times=()

for i in {1..10}; do
    start_time=$(date +%s%3N)
    response=$(curl -s https://zk-evm.org/status)
    end_time=$(date +%s%3N)
    
    response_time=$((end_time - start_time))
    total_time=$((total_time + response_time))
    
    # Extract proving time from JSON response
    proving_time=$(echo "$response" | grep -o '"average_proving_time":[0-9.]*' | cut -d':' -f2)
    
    if [ ! -z "$proving_time" ]; then
        proving_times+=($proving_time)
        echo "  Test $i: ${response_time}ms response - Avg proving: ${proving_time}ms"
    else
        echo "  Test $i: ${response_time}ms response - ERROR parsing JSON"
    fi
    
    sleep 0.5
done

avg_response_time=$((total_time / 10))
echo ""
echo "📊 Status Endpoint Results:"
echo "  Average response time: ${avg_response_time}ms"

# Test 2: Current system metrics
echo ""
echo "⚡ Current System Metrics:"
current_status=$(curl -s https://zk-evm.org/status)
echo "$current_status" | jq . 2>/dev/null || echo "$current_status"

# Extract key metrics
current_proving=$(echo "$current_status" | grep -o '"average_proving_time":[0-9.]*' | cut -d':' -f2)
current_tps=$(echo "$current_status" | grep -o '"tps":[0-9.]*' | cut -d':' -f2)
blocks_proven=$(echo "$current_status" | grep -o '"blocks_proven":[0-9]*' | cut -d':' -f2)
total_tx=$(echo "$current_status" | grep -o '"total_transactions":[0-9]*' | cut -d':' -f2)

echo ""
echo "📈 Key Metrics:"
echo "  Current proving time: ${current_proving}ms"
echo "  Current TPS: ${current_tps}"
echo "  Blocks proven: ${blocks_proven}"
echo "  Total transactions: ${total_tx}"

# Test 3: Load testing with concurrent requests
echo ""
echo "🚀 Testing concurrent request handling (20 requests)..."

# Create temp file for results
temp_file="/tmp/zkvm_concurrent_test.txt"
> "$temp_file"

# Launch 20 concurrent requests
for i in {1..20}; do
    (
        start_time=$(date +%s%3N)
        response=$(curl -s https://zk-evm.org/status)
        end_time=$(date +%s%3N)
        response_time=$((end_time - start_time))
        
        if echo "$response" | grep -q "average_proving_time"; then
            echo "SUCCESS:$response_time" >> "$temp_file"
        else
            echo "FAILED:$response_time" >> "$temp_file"
        fi
    ) &
done

# Wait for all background processes
wait

# Analyze concurrent test results
successful=$(grep -c "SUCCESS" "$temp_file")
total_requests=20
avg_concurrent_time=$(grep "SUCCESS" "$temp_file" | cut -d':' -f2 | awk '{s+=$1} END {print s/NR}')

echo "  Successful requests: $successful/$total_requests"
echo "  Average response time: ${avg_concurrent_time}ms"

# Clean up
rm -f "$temp_file"

# Performance Assessment
echo ""
echo "================================="
echo "📈 PERFORMANCE TEST SUMMARY"
echo "================================="

target_proving_time=100  # Our target from optimizations

echo "Status endpoint avg response: ${avg_response_time}ms"
echo "Current proving time: ${current_proving}ms"
echo "Current TPS: ${current_tps}"
echo "Concurrent request success: $successful/$total_requests"
echo "Concurrent avg response: ${avg_concurrent_time}ms"

echo ""
echo "🎯 PERFORMANCE ASSESSMENT:"

# Proving time assessment
if (( $(echo "$current_proving <= $target_proving_time" | bc -l) )); then
    echo "✅ PROVING TIME: ${current_proving}ms (TARGET: ≤${target_proving_time}ms) - EXCELLENT!"
    proving_status="PASS"
else
    echo "⚠️  PROVING TIME: ${current_proving}ms (TARGET: ≤${target_proving_time}ms) - NEEDS IMPROVEMENT"
    proving_status="FAIL"
fi

# API response assessment
if [ "$avg_response_time" -le 200 ]; then
    echo "✅ API RESPONSE: ${avg_response_time}ms - FAST"
    api_status="PASS"
else
    echo "⚠️  API RESPONSE: ${avg_response_time}ms - SLOW"
    api_status="FAIL"
fi

# Reliability assessment
if [ "$successful" -ge 18 ]; then
    echo "✅ RELIABILITY: $successful/$total_requests requests succeeded - STABLE"
    reliability_status="PASS"
else
    echo "⚠️  RELIABILITY: $successful/$total_requests requests succeeded - UNSTABLE"
    reliability_status="FAIL"
fi

# Final recommendation
echo ""
echo "🚀 DEPLOYMENT RECOMMENDATION:"
if [ "$proving_status" = "PASS" ] && [ "$reliability_status" = "PASS" ]; then
    echo "✅ READY FOR PRODUCTION DEPLOYMENT!"
    echo "   Performance improvements verified. Safe to promote staging to production."
    
    # Show deployment command
    echo ""
    echo "🔧 To promote staging to production, run:"
    echo "   aws ecs update-service --region us-east-1 --cluster zkvm-cluster --service zkvm-production --task-definition \$(aws ecs describe-services --region us-east-1 --cluster zkvm-cluster --services zkvm-staging --query 'services[0].taskDefinition' --output text)"
    
else
    echo "⚠️  NOT READY FOR PRODUCTION"
    echo "   Performance issues detected. Investigate before promoting."
fi
