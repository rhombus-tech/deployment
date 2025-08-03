#!/bin/bash
# SAFEST: Build new image FROM your working base, preserve original
set -e

echo "🛡️ SAFE UPDATE: Building on proven 12:53 PM foundation"

# Your proven working image
WORKING_BASE="211125768252.dkr.ecr.us-east-1.amazonaws.com/zkvm-proving-service:sha256-f3d264ae512b29370de10a88db372e03010614f5de6356e4b00387ad36233c53"
AWS_REGION="us-east-1"
ECR_REGISTRY="211125768252.dkr.ecr.us-east-1.amazonaws.com"
REPOSITORY_NAME="zkvm-proving-service"
NEW_TAG="block-fix-$(date +%Y%m%d-%H%M%S)"

echo "📋 Creating minimal update Dockerfile..."
cat > Dockerfile.safe-update << EOF
# Start FROM your proven working image
FROM ${WORKING_BASE}

# Copy ONLY the updated live proving service file
COPY evm-verify/src/bin/live_proving_service.rs /app/evm-verify/src/bin/live_proving_service.rs

# Rebuild ONLY the live proving service (preserve everything else)
WORKDIR /app/evm-verify
RUN cargo build --bin live-proving-service --release

# Keep same working directory and entry point
WORKDIR /app
EXPOSE 3001
CMD ["./evm-verify/target/release/live-proving-service"]
EOF

echo "🔨 Building safe update (preserves your working foundation)..."
docker build -f Dockerfile.safe-update -t $NEW_TAG .

echo "✅ SUCCESS! New image built: $NEW_TAG"
echo "📦 Original working image preserved: $WORKING_BASE"
echo ""
echo "🚀 To deploy the update:"
echo "1. Tag: docker tag $NEW_TAG $ECR_REGISTRY/$REPOSITORY_NAME:$NEW_TAG"
echo "2. Push: docker push $ECR_REGISTRY/$REPOSITORY_NAME:$NEW_TAG"
echo "3. Update ECS task definition with new image"
echo ""
echo "🔄 To rollback if needed:"
echo "   Use your original working image: $WORKING_BASE"
