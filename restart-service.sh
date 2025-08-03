#!/bin/bash

# Quick script to manually restart the zkEVM service using July 22nd Docker image
# Use this when you notice the service is hung

echo "🔄 Restarting zkEVM Live Proving Service..."
echo "📅 Using July 22nd Docker image (preserving existing deployment)"

# Get the current service configuration
SERVICE_ARN=$(aws ecs describe-services \
  --cluster zkvm-cluster \
  --services zkvm-production \
  --query 'services[0].serviceArn' \
  --output text 2>/dev/null)

if [ "$SERVICE_ARN" = "None" ] || [ -z "$SERVICE_ARN" ]; then
    echo "❌ Service not found. Please check your cluster and service names."
    echo "💡 Available services:"
    aws ecs list-services --cluster zkvm-cluster --query 'serviceArns' --output table
    exit 1
fi

echo "🎯 Found service: $SERVICE_ARN"

# Force new deployment with existing task definition (keeps July 22nd image)
echo "🚀 Triggering force deployment (will restart with same Docker image)..."

aws ecs update-service \
    --cluster zkvm-cluster \
    --service zkvm-production \
    --force-new-deployment

if [ $? -eq 0 ]; then
    echo "✅ Service restart initiated successfully!"
    echo "⏳ New tasks will be started with your July 22nd Docker image"
    echo "🔍 Monitor deployment status:"
    echo "   aws ecs describe-services --cluster zkvm-cluster --services zkvm-production"
    echo ""
    echo "🌐 Service should be available at: https://zk-evm.org/status"
    echo "📊 Check logs: https://console.aws.amazon.com/cloudwatch/home#logsV2:"
else
    echo "❌ Failed to restart service. Check your AWS credentials and permissions."
    exit 1
fi
