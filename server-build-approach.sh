#!/bin/bash
# Build the updated image directly on AWS using ECS Exec
set -e

echo "🔧 BUILDING ON SERVER - No local Docker needed!"

# Get your current ECS task ID
TASK_ARN=$(aws ecs list-tasks --cluster zkvm-cluster --service-name zkvm-production --region us-east-1 --query 'taskArns[0]' --output text)
echo "Current task: $TASK_ARN"

# Upload the updated file to S3 temporarily  
aws s3 cp evm-verify/src/bin/live_proving_service.rs s3://your-bucket/live_proving_service_update.rs --region us-east-1

echo "📋 Connecting to running container to update and rebuild..."
aws ecs execute-command \
  --cluster zkvm-cluster \
  --task ${TASK_ARN} \
  --container zkvm-proving-container \
  --interactive \
  --command "/bin/bash -c '
    cd /app/evm-verify/src/bin
    aws s3 cp s3://your-bucket/live_proving_service_update.rs live_proving_service.rs
    cd /app/evm-verify  
    cargo build --bin live-proving-service --release
    killall live-proving-service || true
    nohup ./target/release/live-proving-service > service.log 2>&1 &
    echo Updated and restarted service successfully!
  '" \
  --region us-east-1

echo "✅ Service updated directly on server!"
