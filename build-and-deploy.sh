#!/bin/bash
set -e

# Build Docker image with optimized proving engine + website
echo "🔨 Building complete zkEVM image with proving engine + website..."
/Applications/Docker.app/Contents/Resources/bin/docker build -f zkevm-cloud-service/Dockerfile -t zkvm-complete:latest .

# Tag for AWS ECR
REPO_URI="586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production"
NEW_TAG="website-optimized-$(date +%Y%m%d-%H%M%S)"

echo "🏷️  Tagging as $NEW_TAG..."
/Applications/Docker.app/Contents/Resources/bin/docker tag zkvm-complete:latest "$REPO_URI:$NEW_TAG"

# Push to ECR
echo "🚀 Pushing to ECR..."
/Applications/Docker.app/Contents/Resources/bin/docker push "$REPO_URI:$NEW_TAG"

echo "✅ Image pushed successfully: $REPO_URI:$NEW_TAG"

# Update ECS task definition with new image
echo "📝 Updating ECS task definition..."
sed "s|586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:.*\",|586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:$NEW_TAG\",|g" temp-task-definition.json > temp-updated-task-def.json

# Register new task definition
echo "📋 Registering new task definition..."
REVISION=$(aws ecs register-task-definition --cli-input-json file://temp-updated-task-def.json --query 'taskDefinition.revision' --output text)

# Update ECS service
echo "🚀 Deploying to ECS service..."
aws ecs update-service --cluster zkvm-cluster --service zkvm-production --task-definition zkvm-production:$REVISION

echo "✅ Deployment complete!"
echo "🌐 Service URL: http://zk-evm.org"
echo "📊 Status endpoint: http://zk-evm.org/status"
echo "📈 Results endpoint: http://zk-evm.org/results"
echo "⏱️  Allow 2-3 minutes for the new service to start and optimize performance"
