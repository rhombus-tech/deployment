#!/bin/bash

# zkEVM Status Monitor and Auto-Restart Script
# Monitors status API for freeze detection and triggers restart when needed

SERVICE_URL="https://zk-evm.org/status"
CLUSTER="zkvm-cluster"
SERVICE="zkvm-production"
FREEZE_THRESHOLD_SECONDS=300  # 5 minutes without updates = frozen

echo "🔍 Starting zkEVM Status Monitor..."
echo "Target: $SERVICE_URL"
echo "Freeze threshold: ${FREEZE_THRESHOLD_SECONDS}s"
echo

# Store previous status for comparison
previous_latest_block=""
previous_blocks_proven=""
last_change_time=$(date +%s)

while true; do
    current_time=$(date +%s)
    
    # Get current status
    status_response=$(curl -s "$SERVICE_URL" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$status_response" ]; then
        # Parse JSON response
        latest_block=$(echo "$status_response" | jq -r '.latest_block // "null"')
        blocks_proven=$(echo "$status_response" | jq -r '.blocks_proven // "null"')
        avg_time=$(echo "$status_response" | jq -r '.average_proving_time // "null"')
        
        echo "$(date): latest_block=$latest_block, blocks_proven=$blocks_proven, avg_time=${avg_time}ms"
        
        # Check if values changed from previous check
        if [ "$latest_block" != "$previous_latest_block" ] || [ "$blocks_proven" != "$previous_blocks_proven" ]; then
            echo "✅ Status updated - service is live"
            last_change_time=$current_time
            previous_latest_block="$latest_block"
            previous_blocks_proven="$blocks_proven"
        else
            # Calculate how long since last change
            time_since_change=$((current_time - last_change_time))
            echo "⏳ No status change for ${time_since_change}s"
            
            # Check if we've exceeded freeze threshold
            if [ $time_since_change -gt $FREEZE_THRESHOLD_SECONDS ]; then
                echo "🚨 FREEZE DETECTED! Status frozen for ${time_since_change}s"
                echo "🔄 Triggering service restart..."
                
                # Force new deployment to restart service
                aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" --force-new-deployment
                
                if [ $? -eq 0 ]; then
                    echo "✅ Service restart triggered successfully"
                    echo "⏳ Waiting 60s for service to restart..."
                    sleep 60
                    last_change_time=$current_time  # Reset timer
                else
                    echo "❌ Failed to trigger service restart"
                fi
            fi
        fi
    else
        echo "❌ Failed to get status response"
    fi
    
    # Wait 30 seconds before next check
    sleep 30
done
