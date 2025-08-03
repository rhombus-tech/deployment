#!/bin/bash

echo "🚀 Deploying zkEVM Production Server to Google Cloud Run"

# Set your project ID here (you'll get this after creating a Google Cloud project)
PROJECT_ID="your-project-id-here"

# Build and deploy to Cloud Run
gcloud run deploy zkvm-production \
    --source . \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --port 8080 \
    --memory 2Gi \
    --cpu 2 \
    --max-instances 10 \
    --project $PROJECT_ID

echo "✅ Deployment complete!"
echo "🌐 Your zkEVM server will be available at: https://zkvm-production-[hash]-uc.a.run.app"
