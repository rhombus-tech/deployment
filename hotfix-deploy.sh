#!/bin/bash
set -e

echo "🔧 Building hotfix for block selection issue on proven working image..."

# Build hotfix image using the working base
echo "🔨 Building hotfix image..."
/Applications/Docker.app/Contents/Resources/bin/docker build -f Dockerfile.hotfix -t zkvm-hotfix:latest .

# Tag for AWS ECR with hotfix label
REPO_URI="586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production"
HOTFIX_TAG="block-selection-hotfix-$(date +%Y%m%d-%H%M%S)"

echo "🏷️  Tagging as $HOTFIX_TAG..."
/Applications/Docker.app/Contents/Resources/bin/docker tag zkvm-hotfix:latest "$REPO_URI:$HOTFIX_TAG"

# Push to ECR
echo "🚀 Pushing hotfix to ECR..."
/Applications/Docker.app/Contents/Resources/bin/docker push "$REPO_URI:$HOTFIX_TAG"

echo "✅ Hotfix image pushed: $REPO_URI:$HOTFIX_TAG"

# Update ECS task definition with hotfix image
echo "📝 Updating ECS task definition with hotfix..."
sed "s|586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production@sha256:.*\",|586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:$HOTFIX_TAG\",|g" temp-task-definition.json > temp-hotfix-task-def.json

# Register new task definition
echo "📋 Registering hotfix task definition..."
REVISION=$(aws ecs register-task-definition --cli-input-json file://temp-hotfix-task-def.json --query 'taskDefinition.revision' --output text)

# Update ECS service
echo "🚀 Deploying hotfix to ECS service..."
aws ecs update-service --cluster zkvm-cluster --service zkvm-production --task-definition zkvm-production:$REVISION

echo "✅ Block selection hotfix deployed successfully!"
echo ""
echo "🔍 What this hotfix fixes:"
echo "   ✓ Eliminates parse errors from future/non-existent blocks"
echo "   ✓ Avoids proving blocks too close to latest (stays 100 blocks behind)"
echo "   ✓ Implements intelligent block bounds checking"
echo "   ✓ Preserves all existing performance optimizations"
echo ""
echo "🌐 Service URL: http://zk-evm.org"
echo "📊 Monitor status: http://zk-evm.org/status"
echo "📈 Live results: http://zk-evm.org/results"
echo "⏱️  Allow 2-3 minutes for service restart with improved block selection"
