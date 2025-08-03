#!/bin/bash

# Setup automated monitoring and preventive maintenance for zkEVM service

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

setup_cloudwatch_alarms() {
    log "🔔 Setting up CloudWatch alarms for zkEVM monitoring"
    
    # Alarm for high CPU usage
    aws cloudwatch put-metric-alarm \
        --alarm-name "zkvm-high-cpu" \
        --alarm-description "zkEVM high CPU usage" \
        --metric-name CPUUtilization \
        --namespace AWS/ECS \
        --statistic Average \
        --period 300 \
        --threshold 80 \
        --comparison-operator GreaterThanThreshold \
        --dimensions Name=ServiceName,Value=zkvm-production Name=ClusterName,Value=zkvm-cluster \
        --evaluation-periods 3 \
        --alarm-actions arn:aws:sns:us-east-1:586794479606:zkvm-alerts
    
    # Alarm for high memory usage  
    aws cloudwatch put-metric-alarm \
        --alarm-name "zkvm-high-memory" \
        --alarm-description "zkEVM high memory usage" \
        --metric-name MemoryUtilization \
        --namespace AWS/ECS \
        --statistic Average \
        --period 300 \
        --threshold 85 \
        --comparison-operator GreaterThanThreshold \
        --dimensions Name=ServiceName,Value=zkvm-production Name=ClusterName,Value=zkvm-cluster \
        --evaluation-periods 2 \
        --alarm-actions arn:aws:sns:us-east-1:586794479606:zkvm-alerts
        
    log "✅ CloudWatch alarms configured"
}

setup_cron_monitoring() {
    log "⏰ Setting up cron job for health monitoring"
    
    # Add health check to crontab (every 5 minutes)
    (crontab -l 2>/dev/null; echo "*/5 * * * * /Users/talzisckind/Downloads/deployment/health-monitor.sh >> /tmp/zkvm-cron.log 2>&1") | crontab -
    
    # Weekly preventive restart (Sunday 2 AM)
    (crontab -l 2>/dev/null; echo "0 2 * * 0 aws ecs update-service --cluster zkvm-cluster --service zkvm-production --force-new-deployment >> /tmp/zkvm-weekly-restart.log 2>&1") | crontab -
    
    log "✅ Cron jobs configured"
}

deploy_improved_task_definition() {
    log "🚀 Deploying improved task definition with more resources"
    
    # Register new task definition
    NEW_TASK_DEF=$(aws ecs register-task-definition --cli-input-json file://improved-task-def.json --query 'taskDefinition.taskDefinitionArn' --output text)
    
    if [ $? -eq 0 ]; then
        log "✅ New task definition registered: $NEW_TASK_DEF"
        
        # Update service to use new task definition
        aws ecs update-service \
            --cluster zkvm-cluster \
            --service zkvm-production \
            --task-definition "$NEW_TASK_DEF" \
            --force-new-deployment
            
        log "✅ Service updated with improved configuration"
    else
        log "❌ Failed to register new task definition"
        return 1
    fi
}

create_metrics_dashboard() {
    log "📊 Creating CloudWatch dashboard for zkEVM metrics"
    
    cat > /tmp/dashboard-body.json << 'EOF'
{
    "widgets": [
        {
            "type": "metric",
            "x": 0,
            "y": 0,
            "width": 12,
            "height": 6,
            "properties": {
                "metrics": [
                    [ "AWS/ECS", "CPUUtilization", "ServiceName", "zkvm-production", "ClusterName", "zkvm-cluster" ],
                    [ ".", "MemoryUtilization", ".", ".", ".", "." ]
                ],
                "period": 300,
                "stat": "Average",
                "region": "us-east-1",
                "title": "zkEVM Resource Utilization"
            }
        },
        {
            "type": "log",
            "x": 0,
            "y": 6,
            "width": 24,
            "height": 6,
            "properties": {
                "query": "SOURCE '/ecs/zkvm-production' | fields @timestamp, @message\n| filter @message like /proved in/\n| sort @timestamp desc\n| limit 20",
                "region": "us-east-1",
                "title": "Recent Block Proofs",
                "view": "table"
            }
        }
    ]
}
EOF

    aws cloudwatch put-dashboard \
        --dashboard-name "zkEVM-Health" \
        --dashboard-body file:///tmp/dashboard-body.json
        
    log "✅ CloudWatch dashboard created"
}

main() {
    log "🏗️  Setting up comprehensive zkEVM monitoring and prevention system"
    
    setup_cloudwatch_alarms
    setup_cron_monitoring  
    deploy_improved_task_definition
    create_metrics_dashboard
    
    log "🎉 Monitoring setup complete!"
    log "📋 Summary of improvements:"
    log "   • Memory increased: 4GB → 8GB"
    log "   • CPU increased: 2 vCPU → 4 vCPU" 
    log "   • Health checks enabled every 30s"
    log "   • Automated monitoring every 5 minutes"
    log "   • Weekly preventive restarts (Sunday 2 AM)"
    log "   • CloudWatch alarms for CPU/memory"
    log "   • Real-time dashboard created"
}

main "$@"
