#!/bin/bash

# zkEVM Health Monitor and Auto-Recovery Script
# Monitors proving time metrics and automatically restarts service if stuck

LOG_FILE="/tmp/zkvm-health.log"
ALERT_THRESHOLD=10  # minutes of stuck proving time
PROVING_TIME_THRESHOLD=400  # ms - if proving time is above this for too long, restart

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

check_status() {
    local status_response=$(curl -s https://zk-evm.org/status)
    echo "$status_response"
}

get_proving_time() {
    local status="$1"
    echo "$status" | jq -r '.average_proving_time // 0'
}

get_latest_block() {
    local status="$1"
    echo "$status" | jq -r '.latest_block // 0'
}

get_uptime() {
    local status="$1"
    echo "$status" | jq -r '.uptime_seconds // 0'
}

restart_service() {
    log "🔄 Auto-restarting zkvm-production service due to stuck proving worker"
    aws ecs update-service --cluster zkvm-cluster --service zkvm-production --force-new-deployment > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log "✅ Service restart initiated successfully"
        # Send notification (could add Slack/email here)
        return 0
    else
        log "❌ Failed to restart service"
        return 1
    fi
}

main() {
    log "🔍 Starting zkEVM health check"
    
    # Get current status
    status=$(check_status)
    if [ $? -ne 0 ] || [ -z "$status" ]; then
        log "❌ Failed to fetch status from zk-evm.org"
        exit 1
    fi
    
    proving_time=$(get_proving_time "$status")
    latest_block=$(get_latest_block "$status")
    uptime=$(get_uptime "$status")
    
    log "📊 Current metrics: proving_time=${proving_time}ms, latest_block=${latest_block}, uptime=${uptime}s"
    
    # Store metrics for comparison
    METRICS_FILE="/tmp/zkvm-metrics.json"
    if [ -f "$METRICS_FILE" ]; then
        prev_block=$(jq -r '.latest_block // 0' "$METRICS_FILE")
        prev_proving_time=$(jq -r '.proving_time // 0' "$METRICS_FILE")
        prev_check_time=$(jq -r '.check_time // 0' "$METRICS_FILE")
        
        current_time=$(date +%s)
        time_diff=$((current_time - prev_check_time))
        
        # Check if blocks are not progressing for > 10 minutes
        if [ "$latest_block" -eq "$prev_block" ] && [ "$time_diff" -gt 600 ]; then
            log "⚠️  WARNING: Latest block stuck at $latest_block for ${time_diff}s"
            restart_service
        # Check if proving time is too high for too long
        elif [ "${proving_time%.*}" -gt "$PROVING_TIME_THRESHOLD" ] && [ "${prev_proving_time%.*}" -gt "$PROVING_TIME_THRESHOLD" ]; then
            log "⚠️  WARNING: Proving time high for consecutive checks: ${proving_time}ms"
            restart_service
        # Check for very long uptime (> 7 days) - preventive restart
        elif [ "${uptime%.*}" -gt 604800 ]; then
            log "⚠️  WARNING: Service uptime > 7 days (${uptime}s), performing preventive restart"
            restart_service
        else
            log "✅ Service health OK"
        fi
    else
        log "📝 First health check, storing baseline metrics"
    fi
    
    # Store current metrics
    cat > "$METRICS_FILE" << EOF
{
    "proving_time": $proving_time,
    "latest_block": $latest_block,
    "uptime": $uptime,
    "check_time": $(date +%s)
}
EOF
    
    log "🏁 Health check completed"
}

main "$@"
