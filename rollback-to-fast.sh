#!/bin/bash

# Emergency Rollback to High-Performance 12:53 PM Image
set -e

echo "🚨 ROLLING BACK TO HIGH-PERFORMANCE IMAGE..."
echo "   Target: 12:53 PM image (sub-100ms proving)"

# The proven fast image digest
FAST_IMAGE="586794479606.dkr.ecr.us-east-1.amazonaws.com/zkvm-production@sha256:f3d264ae512b29370de10a88db372e03010614f5de6356e4b00387ad36233c53"

echo "📝 Getting current task definition..."
aws ecs describe-task-definition \
    --task-definition zkvm-production \
    --region us-east-1 \
    --query 'taskDefinition' > current-task-def.json

echo "🔄 Updating to fast image..."
jq --arg img "$FAST_IMAGE" '.containerDefinitions[0].image = $img | del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .placementConstraints, .compatibilities, .registeredAt, .registeredBy)' current-task-def.json > rollback-task-def.json

echo "📋 Registering rollback task definition..."
NEW_TASK_ARN=$(aws ecs register-task-definition \
    --region us-east-1 \
    --cli-input-json file://rollback-task-def.json \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

echo "🚀 Deploying rollback..."
aws ecs update-service \
    --cluster zkvm-cluster \
    --service zkvm-production \
    --task-definition zkvm-production \
    --region us-east-1 \
    --force-new-deployment \
    --query 'service.serviceName'

echo "✅ ROLLBACK INITIATED!"
echo "🎯 Expected: Sub-100ms proving times restored"
echo "🔗 Monitor: http://zk-evm.org"
echo "⏱️ ETA: 2-3 minutes for deployment"

# Cleanup
rm -f current-task-def.json rollback-task-def.json

echo ""
echo "📊 NEXT STEPS:"
echo "1. Wait for deployment (2-3 min)"
echo "2. Verify sub-100ms performance restored"
echo "3. Create proper patch with block fixes on fast image"
