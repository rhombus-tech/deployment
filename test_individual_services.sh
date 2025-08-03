#!/bin/bash

echo "🎯 INDIVIDUAL SERVICE PERFORMANCE TEST"
echo "======================================"
echo "Testing both staging and production services directly"
echo "Test time: $(date)"
echo ""

STAGING_IP="54.209.144.67:8080"
PRODUCTION_IP="52.90.110.220:8080"

echo "🔵 STAGING SERVICE TEST (${STAGING_IP})"
echo "=================================================="

# Test staging service
staging_results=()
for i in {1..5}; do
    echo -n "  Staging test $i: "
    result=$(curl -s --connect-timeout 10 http://${STAGING_IP}/status)
    
    if [ $? -eq 0 ] && echo "$result" | grep -q "average_proving_time"; then
        proving_time=$(echo "$result" | grep -o '"average_proving_time":[0-9.]*' | cut -d':' -f2)
        tps=$(echo "$result" | grep -o '"tps":[0-9.]*' | cut -d':' -f2)
        blocks=$(echo "$result" | grep -o '"blocks_proven":[0-9]*' | cut -d':' -f2)
        
        staging_results+=($proving_time)
        echo "Proving: ${proving_time}ms | TPS: ${tps} | Blocks: ${blocks}"
    else
        echo "❌ FAILED - Connection timeout or invalid response"
    fi
    sleep 1
done

echo ""
echo "🔴 PRODUCTION SERVICE TEST (${PRODUCTION_IP})"
echo "====================================================="

# Test production service
production_results=()
for i in {1..5}; do
    echo -n "  Production test $i: "
    result=$(curl -s --connect-timeout 10 http://${PRODUCTION_IP}/status)
    
    if [ $? -eq 0 ] && echo "$result" | grep -q "average_proving_time"; then
        proving_time=$(echo "$result" | grep -o '"average_proving_time":[0-9.]*' | cut -d':' -f2)
        tps=$(echo "$result" | grep -o '"tps":[0-9.]*' | cut -d':' -f2)
        blocks=$(echo "$result" | grep -o '"blocks_proven":[0-9]*' | cut -d':' -f2)
        
        production_results+=($proving_time)
        echo "Proving: ${proving_time}ms | TPS: ${tps} | Blocks: ${blocks}"
    else
        echo "❌ FAILED - Connection timeout or invalid response"
    fi
    sleep 1
done

echo ""
echo "📊 PERFORMANCE COMPARISON"
echo "========================="

# Calculate averages if we have results
if [ ${#staging_results[@]} -gt 0 ]; then
    staging_avg=$(printf '%s\n' "${staging_results[@]}" | awk '{s+=$1} END {print s/NR}')
    echo "🔵 Staging average proving time: ${staging_avg}ms"
else
    echo "🔵 Staging: No successful responses"
    staging_avg=999999
fi

if [ ${#production_results[@]} -gt 0 ]; then
    production_avg=$(printf '%s\n' "${production_results[@]}" | awk '{s+=$1} END {print s/NR}')
    echo "🔴 Production average proving time: ${production_avg}ms"
else
    echo "🔴 Production: No successful responses"
    production_avg=999999
fi

echo "🎯 Target proving time: ≤100ms"
echo ""

# Performance analysis
echo "🚀 ANALYSIS:"
if (( $(echo "$staging_avg < $production_avg" | bc -l) )); then
    improvement=$(echo "scale=1; ($production_avg - $staging_avg) / $production_avg * 100" | bc)
    echo "✅ Staging is ${improvement}% faster than production!"
else
    echo "⚠️  Staging is not faster than production"
fi

if (( $(echo "$staging_avg <= 100" | bc -l) )); then
    echo "✅ Staging meets performance target (≤100ms)"
    staging_ready="YES"
else
    echo "⚠️  Staging does not meet performance target"
    staging_ready="NO"
fi

echo ""
echo "🔧 DEPLOYMENT RECOMMENDATION:"
if [ "$staging_ready" = "YES" ]; then
    echo "✅ PROMOTE STAGING TO PRODUCTION"
    echo "   Staging service shows excellent performance!"
    echo ""
    echo "   Command to promote staging to production:"
    echo "   aws ecs update-service --region us-east-1 --cluster zkvm-cluster \\"
    echo "     --service zkvm-production \\"
    echo "     --task-definition \$(aws ecs describe-services --region us-east-1 --cluster zkvm-cluster --services zkvm-staging --query 'services[0].taskDefinition' --output text)"
elif (( $(echo "$staging_avg < $production_avg" | bc -l) )); then
    echo "🔄 STAGING SHOWS IMPROVEMENT"
    echo "   Consider promoting even though target not fully met"
else
    echo "⚠️  INVESTIGATE PERFORMANCE ISSUES"
    echo "   Both services need optimization"
fi

echo ""
echo "📈 Summary:"
echo "   Staging:    ${staging_avg}ms"
echo "   Production: ${production_avg}ms"
echo "   Target:     ≤100ms"
