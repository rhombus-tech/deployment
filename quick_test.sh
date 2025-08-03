#!/bin/bash

echo "🔍 Quick Performance Analysis - $(date)"
echo "=========================="

for i in {1..5}; do
    echo -n "Test $i: "
    result=$(curl -s https://zk-evm.org/status)
    proving_time=$(echo "$result" | grep -o '"average_proving_time":[0-9.]*' | cut -d':' -f2)
    tps=$(echo "$result" | grep -o '"tps":[0-9.]*' | cut -d':' -f2)
    blocks=$(echo "$result" | grep -o '"blocks_proven":[0-9]*' | cut -d':' -f2)
    
    echo "Proving: ${proving_time}ms | TPS: ${tps} | Blocks: ${blocks}"
    sleep 2
done

echo ""
echo "🎯 Analysis:"
echo "Current performance: ~${proving_time}ms proving time"
echo "Target performance: ≤100ms"
echo ""

if (( $(echo "$proving_time > 200" | bc -l) )); then
    echo "⚠️  Performance is significantly below target"
    echo "   This suggests optimizations may not be fully active"
    echo "   or there may be a configuration issue"
    echo ""
    echo "🔧 Recommended actions:"
    echo "1. Check if the system needs warm-up time"
    echo "2. Verify optimization settings are enabled"
    echo "3. Check for any error logs in CloudWatch"
    echo "4. Consider restarting services to reload optimizations"
else
    echo "✅ Performance is reasonable, may need fine-tuning"
fi
