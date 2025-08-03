#!/bin/bash
set -e

echo "🚀 DEPLOYING LIVE PROVING SERVICE UPDATE"
echo "Base: Working 12:53 PM image (sub-100ms performance)"
echo "Update: Block availability fixes + demo path corrections"

# AWS Configuration
AWS_REGION="us-east-1"
ECR_REGISTRY="211125768252.dkr.ecr.us-east-1.amazonaws.com"
REPOSITORY_NAME="zkvm-proving-service"
IMAGE_TAG="live-service-update-$(date +%Y%m%d-%H%M%S)"

echo "📦 Building updated Docker image with live service fixes..."

# Create Dockerfile that builds on 12:53 PM working foundation
cat > Dockerfile.live-service-update << 'EOF'
# Start with our proven working 12:53 PM base image
FROM 211125768252.dkr.ecr.us-east-1.amazonaws.com/zkvm-proving-service:sha256-f3d264ae512b29370de10a88db372e03010614f5de6356e4b00387ad36233c53

# Update only the live proving service file with block availability fixes
COPY evm-verify/src/bin/live_proving_service.rs /app/evm-verify/src/bin/live_proving_service.rs

# Rebuild only the live proving service binary (preserve everything else)
WORKDIR /app/evm-verify
RUN cargo build --bin live-proving-service --release

# Keep the same working directory and entry point from 12:53 PM image
WORKDIR /app
EXPOSE 3001

# Use the updated live proving service binary
CMD ["./evm-verify/target/release/live-proving-service"]
EOF

echo "🔧 Building Docker image: $IMAGE_TAG"
/Applications/Docker.app/Contents/Resources/bin/docker build -f Dockerfile.live-service-update -t $IMAGE_TAG .

echo "🏷️ Tagging image for ECR..."
/Applications/Docker.app/Contents/Resources/bin/docker tag $IMAGE_TAG $ECR_REGISTRY/$REPOSITORY_NAME:$IMAGE_TAG
/Applications/Docker.app/Contents/Resources/bin/docker tag $IMAGE_TAG $ECR_REGISTRY/$REPOSITORY_NAME:latest-live-service

echo "📤 Pushing to ECR..."
aws ecr get-login-password --region $AWS_REGION | /Applications/Docker.app/Contents/Resources/bin/docker login --username AWS --password-stdin $ECR_REGISTRY
/Applications/Docker.app/Contents/Resources/bin/docker push $ECR_REGISTRY/$REPOSITORY_NAME:$IMAGE_TAG
/Applications/Docker.app/Contents/Resources/bin/docker push $ECR_REGISTRY/$REPOSITORY_NAME:latest-live-service

echo "🚀 Updating ECS Task Definition..."
# Get current task definition
CURRENT_TASK_DEF=$(aws ecs describe-task-definition --task-definition zkvm-proving-task --region $AWS_REGION)

# Update with new image
NEW_TASK_DEF=$(echo $CURRENT_TASK_DEF | jq --arg IMAGE "$ECR_REGISTRY/$REPOSITORY_NAME:$IMAGE_TAG" '
  .taskDefinition | 
  .containerDefinitions[0].image = $IMAGE |
  del(.taskDefinitionArn) | del(.revision) | del(.status) | 
  del(.requiresAttributes) | del(.placementConstraints) | 
  del(.compatibilities) | del(.registeredAt) | del(.registeredBy)
')

# Register new task definition
echo $NEW_TASK_DEF > new-task-definition.json
NEW_TASK_ARN=$(aws ecs register-task-definition --cli-input-json file://new-task-definition.json --region $AWS_REGION --query 'taskDefinition.taskDefinitionArn' --output text)

echo "📋 New Task Definition: $NEW_TASK_ARN"

echo "🔄 Updating ECS Service..."
aws ecs update-service \
  --cluster zkvm-cluster \
  --service zkvm-production \
  --task-definition $NEW_TASK_ARN \
  --region $AWS_REGION \
  --force-new-deployment

echo "✅ DEPLOYMENT INITIATED!"
echo "🌐 Service URL: http://zk-evm.org"
echo "📊 Monitor deployment:"
echo "   aws ecs describe-services --cluster zkvm-cluster --services zkvm-production --region $AWS_REGION"
echo ""
echo "🎯 Expected Results:"
echo "   • Preserved sub-100ms proving performance from 12:53 PM base"
echo "   • Fixed block availability errors (no more 212ms overhead)"
echo "   • Working demo interface with corrected paths"
echo "   • Better error classification and metrics"

# Cleanup
rm -f Dockerfile.live-service-update new-task-definition.json

echo "🏁 Deployment script completed successfully!"
