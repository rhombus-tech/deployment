#!/bin/bash

echo "🚀 Deploying stable zkEVM proving service from July 22 12:53..."
echo "Image: zkvm-production@sha256:f3d264ae512b29370de10a88db372e03010614f5de6356e4b00387ad36233c53"

# Register new task definition with stable image
echo "📝 Registering new task definition..."
aws ecs register-task-definition \
  --cli-input-json file://rollback-to-stable-1253.json \
  --region us-east-1

if [ $? -ne 0 ]; then
  echo "❌ Failed to register task definition"
  exit 1
fi

echo "✅ Task definition registered successfully"

# Get the new task definition revision
TASK_DEF_ARN=$(aws ecs describe-task-definition \
  --task-definition zkvm-production \
  --region us-east-1 \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo "📋 New task definition: $TASK_DEF_ARN"

# Update the ECS service to use the new task definition
echo "🔄 Updating ECS service..."
aws ecs update-service \
  --cluster zkvm-cluster \
  --service zkvm-production \
  --task-definition zkvm-production \
  --region us-east-1

if [ $? -ne 0 ]; then
  echo "❌ Failed to update ECS service"
  exit 1
fi

echo "✅ ECS service updated successfully"

# Wait for service to stabilize
echo "⏳ Waiting for service to stabilize..."
aws ecs wait services-stable \
  --cluster zkvm-cluster \
  --services zkvm-service \
  --region us-east-1

if [ $? -eq 0 ]; then
  echo "🎉 Deployment completed successfully!"
  echo "🌐 Service should be available at: https://zkevm-live.loca.lt"
  
  # Check service status
  echo "📊 Current service status:"
  aws ecs describe-services \
    --cluster zkvm-cluster \
    --services zkvm-production \
    --region us-east-1 \
    --query 'services[0].deployments[0].{Status:status,TaskDefinition:taskDefinition,RunningCount:runningCount,DesiredCount:desiredCount}'
else
  echo "⚠️  Service deployment may still be in progress"
  exit 1
fi
