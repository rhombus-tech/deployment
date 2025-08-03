#!/bin/bash
set -e

echo "🚀 Building and deploying interactive zkEVM website"

# Build the Docker image with updated website
echo "🔨 Building Docker image..."
docker buildx build --platform linux/amd64 -f zkevm-cloud-service/Dockerfile -t zkvm-production:website-interactive . --load

# Tag for ECR
echo "🏷️  Tagging for ECR..."
docker tag zkvm-production:website-interactive 586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:website-interactive

# Push to ECR
echo "📤 Pushing to ECR..."
docker push 586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:website-interactive

# Create new task definition
echo "📋 Creating new task definition..."
aws ecs register-task-definition \
  --family zkvm-production \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 1024 \
  --memory 2048 \
  --execution-role-arn arn:aws:iam::586794479606:role/ecsTaskExecutionRole \
  --container-definitions '[{
    "name": "zkvm-container",
    "image": "586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:website-interactive",
    "portMappings": [{
      "containerPort": 8080,
      "protocol": "tcp"
    }],
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/zkvm-production",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }]' \
  --region us-east-1

# Update the service
echo "🔄 Updating ECS service..."
aws ecs update-service \
  --cluster zkvm-cluster \
  --service zkvm-production \
  --task-definition zkvm-production \
  --region us-east-1

echo "✅ Deployment initiated! Check ECS console for progress."
echo "🌐 Website will be live at http://zk-evm.org once deployment completes."
