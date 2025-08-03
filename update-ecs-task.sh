#!/bin/bash

# Update ECS Task Definition with New zkEVM Block Fix Image
set -e

echo "🚀 Updating ECS Task Definition with Block Fix Image..."

# Get current task definition
aws ecs describe-task-definition \
    --task-definition zkvm-production \
    --region us-east-1 \
    --query 'taskDefinition' > current-task-def.json

# Update the image in the task definition
NEW_IMAGE="586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production:block-fix-20250722-220631"

# Create new task definition with updated image
jq --arg img "$NEW_IMAGE" '.containerDefinitions[0].image = $img | del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .placementConstraints, .compatibilities, .registeredAt, .registeredBy)' current-task-def.json > new-task-def.json

echo "📝 Registering new task definition..."
aws ecs register-task-definition \
    --region us-east-1 \
    --cli-input-json file://new-task-def.json \
    --query 'taskDefinition.taskDefinitionArn'

echo "🔄 Updating ECS service..."
aws ecs update-service \
    --cluster zkvm-cluster \
    --service zkvm-production \
    --task-definition zkvm-production \
    --region us-east-1 \
    --force-new-deployment

echo "✅ Deployment initiated! The zkEVM service will restart with block availability fixes."
echo "🔗 Monitor at: http://zk-evm.org"

# Cleanup
rm -f current-task-def.json new-task-def.json

echo "🎯 Expected improvements:"
echo "  - Null block detection and graceful handling"
echo "  - Better error classification (data_unavailable_blocks, parsing_errors, network_errors)"  
echo "  - No more parse failures from future/too-recent blocks"
echo "  - Maintained sub-100ms proving performance"
