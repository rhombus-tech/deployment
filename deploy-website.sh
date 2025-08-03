#!/bin/bash
set -e

echo "Building zkEVM server with integrated website..."

# Build the Docker image
docker buildx build --platform linux/amd64 -f zkevm-cloud-service/Dockerfile -t zkvm-website:latest . --load

# Tag for ECR
docker tag zkvm-website:latest 586794479606.dkr.ecr.us-east-1.amazonaws.com/zkevm-production:website

echo "✅ Build complete! Ready to push to ECR and deploy."
echo ""
echo "Next steps:"
echo "1. Push to ECR: docker push 586794479606.dkr.ecr.us-east-1.amazonaws.com/zkevm-production:website"
echo "2. Update ECS task definition with new image URI"
echo "3. Deploy to ECS service"
