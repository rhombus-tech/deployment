#!/bin/bash

echo "🚀 Deploying zkEVM Production Server to AWS ECS"

# Variables you'll need to set
REGION="us-east-1"
CLUSTER_NAME="zkvm-cluster"
SERVICE_NAME="zkvm-production"
ECR_REPO="zkvm-production"

echo "Step 1: Installing AWS CLI..."
if ! command -v aws &> /dev/null; then
    echo "Installing AWS CLI..."
    curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
    sudo installer -pkg AWSCLIV2.pkg -target /
fi

echo "Step 2: Configure AWS credentials..."
echo "⚠️  Run: aws configure"
echo "    Enter your AWS Access Key ID"
echo "    Enter your AWS Secret Access Key"
echo "    Default region: us-east-1"
echo "    Default output: json"

echo "Step 3: Get your AWS Account ID..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "ACCOUNT_ID_HERE")
echo "Account ID: $ACCOUNT_ID"

echo "Step 4: Create ECR repository..."
aws ecr create-repository --repository-name $ECR_REPO --region $REGION 2>/dev/null || echo "Repository may already exist"

echo "Step 5: Build and push Docker image..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

docker build -t $ECR_REPO .
docker tag $ECR_REPO:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest

echo "Step 6: Create ECS cluster..."
aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $REGION

echo "Step 7: Register task definition..."
# Update the task definition with actual account ID
sed "s/ACCOUNT_ID/$ACCOUNT_ID/g" aws-deploy.json > aws-deploy-final.json
aws ecs register-task-definition --cli-input-json file://aws-deploy-final.json --region $REGION

echo "Step 8: Create ECS service..."
aws ecs create-service \
    --cluster $CLUSTER_NAME \
    --service-name $SERVICE_NAME \
    --task-definition zkvm-production:1 \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[subnet-12345],securityGroups=[sg-12345],assignPublicIp=ENABLED}" \
    --region $REGION

echo "✅ Deployment initiated!"
echo "🌐 Your zkEVM server will be available at the ECS service URL"
echo "📊 Monitor at: https://console.aws.amazon.com/ecs/"
