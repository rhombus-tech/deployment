#!/bin/bash

# zkEVM Monitoring Dashboard
# Shows real-time service health and metrics

echo "🔍 zkEVM Service Health Dashboard"
echo "=================================="

# Service Status
echo "📊 Service Status:"
status=$(curl -s https://zk-evm.org/status)
if [ $? -eq 0 ] && [ -n "$status" ]; then
    echo "✅ Service Online"
    echo "   Latest Block: $(echo "$status" | jq -r '.latest_block')"
    echo "   Proving Time: $(echo "$status" | jq -r '.average_proving_time')ms"
    echo "   TPS: $(echo "$status" | jq -r '.tps')"
    echo "   Uptime: $(echo "$status" | jq -r '.uptime_seconds')s"
    echo "   Blocks Proven: $(echo "$status" | jq -r '.blocks_proven')"
else
    echo "❌ Service Offline"
fi

echo ""

# ECS Service Status
echo "🚀 ECS Service Status:"
service_info=$(aws ecs describe-services --cluster zkvm-cluster --services zkvm-production --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}' --output json)
echo "   Status: $(echo "$service_info" | jq -r '.Status')"
echo "   Running Tasks: $(echo "$service_info" | jq -r '.Running')/$(echo "$service_info" | jq -r '.Desired')"

echo ""

# Target Health
echo "🎯 Load Balancer Targets:"
aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:us-east-1:586794479606:targetgroup/zkvm-targets/d5833ab3829026c7 --query 'TargetHealthDescriptions[*].{IP:Target.Id,Health:TargetHealth.State}' --output table

echo ""

# Recent Health Monitor Logs
echo "📋 Recent Health Monitor Activity:"
if [ -f "/tmp/zkvm-health.log" ]; then
    tail -5 /tmp/zkvm-health.log
else
    echo "   No health monitor logs found"
fi

echo ""
echo "💡 Auto-monitoring: Every 5 minutes via cron"
echo "🔧 Manual restart: ./restart-service.sh"
