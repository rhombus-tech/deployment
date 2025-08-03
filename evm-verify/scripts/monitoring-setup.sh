#!/bin/bash

# ZODA-WARP zkEVM Monitoring Stack Setup
# Comprehensive monitoring with Prometheus, Grafana, and custom zkEVM metrics

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
NAMESPACE="zkevm-system"
MONITORING_NAMESPACE="zkevm-monitoring"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-$(openssl rand -base64 32)}"
PROMETHEUS_RETENTION="${PROMETHEUS_RETENTION:-15d}"
GRAFANA_VERSION="${GRAFANA_VERSION:-latest}"
PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-latest}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create monitoring namespace
create_monitoring_namespace() {
    log_info "📦 Creating monitoring namespace..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: $MONITORING_NAMESPACE
  labels:
    name: zkevm-monitoring
    app.kubernetes.io/component: monitoring
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: monitoring-quota
  namespace: $MONITORING_NAMESPACE
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 4Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    persistentvolumeclaims: "10"
EOF
    
    log_success "Monitoring namespace created"
}

# Setup Prometheus
setup_prometheus() {
    log_info "📊 Setting up Prometheus..."
    
    # Create Prometheus RBAC
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: prometheus
  namespace: $MONITORING_NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus
rules:
- apiGroups: [""]
  resources:
  - nodes
  - nodes/proxy
  - services
  - endpoints
  - pods
  verbs: ["get", "list", "watch"]
- apiGroups:
  - extensions
  resources:
  - ingresses
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: prometheus
subjects:
- kind: ServiceAccount
  name: prometheus
  namespace: $MONITORING_NAMESPACE
EOF

    # Create Prometheus ConfigMap
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: $MONITORING_NAMESPACE
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
      external_labels:
        cluster: 'zkevm-production'
        environment: 'production'
    
    rule_files:
      - "/etc/prometheus/rules/*.yml"
    
    alerting:
      alertmanagers:
        - static_configs:
            - targets:
              - alertmanager:9093
    
    scrape_configs:
      # Kubernetes API server
      - job_name: 'kubernetes-apiservers'
        kubernetes_sd_configs:
        - role: endpoints
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
          action: keep
          regex: default;kubernetes;https
      
      # Kubernetes nodes
      - job_name: 'kubernetes-nodes'
        kubernetes_sd_configs:
        - role: node
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - action: labelmap
          regex: __meta_kubernetes_node_label_(.+)
        - target_label: __address__
          replacement: kubernetes.default.svc:443
        - source_labels: [__meta_kubernetes_node_name]
          regex: (.+)
          target_label: __metrics_path__
          replacement: /api/v1/nodes/\${1}/proxy/metrics
      
      # Kubernetes pods
      - job_name: 'kubernetes-pods'
        kubernetes_sd_configs:
        - role: pod
        relabel_configs:
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
          action: keep
          regex: true
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
          action: replace
          target_label: __metrics_path__
          regex: (.+)
        - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
          action: replace
          regex: ([^:]+)(?::\d+)?;(\d+)
          replacement: \$1:\$2
          target_label: __address__
        - action: labelmap
          regex: __meta_kubernetes_pod_label_(.+)
        - source_labels: [__meta_kubernetes_namespace]
          action: replace
          target_label: kubernetes_namespace
        - source_labels: [__meta_kubernetes_pod_name]
          action: replace
          target_label: kubernetes_pod_name
      
      # ZKEVM specific metrics
      - job_name: 'zkevm-server'
        static_configs:
          - targets: ['zkevm-service.zkevm-system:9090']
        scrape_interval: 5s
        metrics_path: /metrics
        scheme: http
        relabel_configs:
        - source_labels: [__address__]
          target_label: instance
        - target_label: job
          replacement: zkevm-server
        - target_label: service
          replacement: zoda-warp
      
      # ZKEVM Load Balancer
      - job_name: 'zkevm-load-balancer'
        static_configs:
          - targets: ['zkevm-load-balancer.zkevm-system:8080']
        scrape_interval: 10s
        metrics_path: /nginx_status
        scheme: http
      
      # Node Exporter (if deployed)
      - job_name: 'node-exporter'
        kubernetes_sd_configs:
        - role: endpoints
        relabel_configs:
        - source_labels: [__meta_kubernetes_endpoints_name]
          regex: 'node-exporter'
          action: keep
      
      # cAdvisor for container metrics
      - job_name: 'kubernetes-cadvisor'
        kubernetes_sd_configs:
        - role: node
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - action: labelmap
          regex: __meta_kubernetes_node_label_(.+)
        - target_label: __address__
          replacement: kubernetes.default.svc:443
        - source_labels: [__meta_kubernetes_node_name]
          regex: (.+)
          target_label: __metrics_path__
          replacement: /api/v1/nodes/\${1}/proxy/metrics/cadvisor
  
  alert_rules.yml: |
    groups:
    - name: zkevm.rules
      rules:
      # zkEVM Performance Alerts
      - alert: ZkEVMHighProvingLatency
        expr: zkevm_proving_time_seconds > 1.0
        for: 2m
        labels:
          severity: warning
          service: zkevm
        annotations:
          summary: "zkEVM proving latency is high"
          description: "zkEVM proving time has been above 1 second for more than 2 minutes. Current value: {{ \$value }}s"
      
      - alert: ZkEVMProvingFailureRate
        expr: rate(zkevm_proofs_failed_total[5m]) / rate(zkevm_proofs_total[5m]) > 0.01
        for: 1m
        labels:
          severity: critical
          service: zkevm
        annotations:
          summary: "High zkEVM proving failure rate"
          description: "zkEVM proving failure rate is {{ \$value | humanizePercentage }} over the last 5 minutes"
      
      - alert: ZkEVMServiceDown
        expr: up{job="zkevm-server"} == 0
        for: 30s
        labels:
          severity: critical
          service: zkevm
        annotations:
          summary: "zkEVM service is down"
          description: "zkEVM service has been down for more than 30 seconds"
      
      - alert: ZkEVMHighMemoryUsage
        expr: zkevm_memory_usage_bytes / zkevm_memory_limit_bytes > 0.9
        for: 5m
        labels:
          severity: warning
          service: zkevm
        annotations:
          summary: "zkEVM high memory usage"
          description: "zkEVM memory usage is above 90% for more than 5 minutes"
      
      - alert: ZkEVMHighCPUUsage
        expr: rate(zkevm_cpu_usage_seconds[5m]) > 0.8
        for: 5m
        labels:
          severity: warning
          service: zkevm
        annotations:
          summary: "zkEVM high CPU usage"
          description: "zkEVM CPU usage is above 80% for more than 5 minutes"
      
      # Kubernetes Cluster Alerts
      - alert: KubernetesPodCrashLooping
        expr: rate(kube_pod_container_status_restarts_total[5m]) * 60 * 5 > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Pod is crash looping"
          description: "Pod {{ \$labels.namespace }}/{{ \$labels.pod }} is crash looping"
      
      - alert: KubernetesNodeNotReady
        expr: kube_node_status_condition{condition="Ready",status="true"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Kubernetes node not ready"
          description: "Node {{ \$labels.node }} has been not ready for more than 5 minutes"
EOF

    # Create Prometheus Deployment
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-server
  namespace: $MONITORING_NAMESPACE
  labels:
    app: prometheus-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus-server
  template:
    metadata:
      labels:
        app: prometheus-server
    spec:
      serviceAccountName: prometheus
      containers:
      - name: prometheus
        image: prom/prometheus:$PROMETHEUS_VERSION
        args:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus/'
          - '--web.console.libraries=/etc/prometheus/console_libraries'
          - '--web.console.templates=/etc/prometheus/consoles'
          - '--storage.tsdb.retention.time=$PROMETHEUS_RETENTION'
          - '--web.enable-lifecycle'
          - '--web.enable-admin-api'
        ports:
        - containerPort: 9090
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2
            memory: 4Gi
        volumeMounts:
        - name: prometheus-config-volume
          mountPath: /etc/prometheus/
        - name: prometheus-storage-volume
          mountPath: /prometheus/
        livenessProbe:
          httpGet:
            path: /
            port: 9090
          initialDelaySeconds: 30
          timeoutSeconds: 30
        readinessProbe:
          httpGet:
            path: /
            port: 9090
          initialDelaySeconds: 30
          timeoutSeconds: 30
      volumes:
      - name: prometheus-config-volume
        configMap:
          defaultMode: 420
          name: prometheus-config
      - name: prometheus-storage-volume
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus-service
  namespace: $MONITORING_NAMESPACE
  annotations:
    prometheus.io/scrape: 'true'
    prometheus.io/port: '9090'
spec:
  selector:
    app: prometheus-server
  type: NodePort
  ports:
    - port: 8080
      targetPort: 9090
      nodePort: 30090
EOF

    log_success "Prometheus setup completed"
}

# Setup Grafana
setup_grafana() {
    log_info "📈 Setting up Grafana..."
    
    # Create Grafana ConfigMap
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasources
  namespace: $MONITORING_NAMESPACE
data:
  prometheus.yaml: |-
    {
        "apiVersion": 1,
        "datasources": [
            {
               "access":"proxy",
                "editable": true,
                "name": "prometheus",
                "orgId": 1,
                "type": "prometheus",
                "url": "http://prometheus-service:8080",
                "version": 1
            }
        ]
    }
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboards-config
  namespace: $MONITORING_NAMESPACE
data:
  dashboards.yaml: |-
    {
        "apiVersion": 1,
        "providers": [
            {
                "folder": "zkEVM",
                "name": "zkevm",
                "options": {
                    "path": "/grafana-dashboard-definitions/zkevm"
                },
                "orgId": 1,
                "type": "file"
            }
        ]
    }
EOF

    # Create Grafana Dashboard ConfigMap from our dashboard file
    kubectl create configmap grafana-dashboard-zkevm \
        --from-file=../monitoring/grafana-dashboard.json \
        -n "$MONITORING_NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -

    # Create Grafana Secret
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: grafana
  namespace: $MONITORING_NAMESPACE
type: Opaque
data:
  admin-user: $(echo -n "admin" | base64 -w0)
  admin-password: $(echo -n "$GRAFANA_ADMIN_PASSWORD" | base64 -w0)
EOF

    # Create Grafana Deployment
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: $MONITORING_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      name: grafana
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:$GRAFANA_VERSION
        ports:
        - name: grafana
          containerPort: 3000
        resources:
          limits:
            memory: "1Gi"
            cpu: "500m"
          requests:
            memory: 512Mi
            cpu: "200m"
        volumeMounts:
          - mountPath: /var/lib/grafana
            name: grafana-storage
          - mountPath: /etc/grafana/provisioning/datasources
            name: grafana-datasources
            readOnly: false
          - mountPath: /etc/grafana/provisioning/dashboards
            name: grafana-dashboards-config
            readOnly: false
          - mountPath: /grafana-dashboard-definitions/zkevm
            name: grafana-dashboard-zkevm
            readOnly: false
        env:
        - name: GF_SECURITY_ADMIN_USER
          valueFrom:
            secretKeyRef:
              name: grafana
              key: admin-user
        - name: GF_SECURITY_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: grafana
              key: admin-password
        - name: GF_USERS_ALLOW_SIGN_UP
          value: "false"
        - name: GF_SERVER_DOMAIN
          value: "grafana.zkevm.example.com"
        - name: GF_SERVER_ROOT_URL
          value: "https://grafana.zkevm.example.com"
      volumes:
        - name: grafana-storage
          emptyDir: {}
        - name: grafana-datasources
          configMap:
              defaultMode: 420
              name: grafana-datasources
        - name: grafana-dashboards-config
          configMap:
              defaultMode: 420
              name: grafana-dashboards-config
        - name: grafana-dashboard-zkevm
          configMap:
              defaultMode: 420
              name: grafana-dashboard-zkevm
---
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: $MONITORING_NAMESPACE
  annotations:
      prometheus.io/scrape: 'true'
      prometheus.io/port: '3000'
spec:
  selector:
    app: grafana
  type: NodePort
  ports:
    - port: 3000
      targetPort: 3000
      nodePort: 30030
EOF

    log_success "Grafana setup completed"
    log_info "Grafana admin password: $GRAFANA_ADMIN_PASSWORD"
}

# Setup alerting
setup_alertmanager() {
    log_info "🚨 Setting up Alertmanager..."
    
    # Create Alertmanager ConfigMap
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: alertmanager-config
  namespace: $MONITORING_NAMESPACE
data:
  config.yml: |-
    global:
      smtp_smarthost: 'localhost:587'
      smtp_from: 'alerts@zkevm.example.com'
    
    route:
      group_by: ['alertname']
      group_wait: 10s
      group_interval: 10s
      repeat_interval: 1h
      receiver: 'web.hook'
      routes:
      - match:
          severity: critical
        receiver: 'critical-alerts'
      - match:
          service: zkevm
        receiver: 'zkevm-alerts'
    
    receivers:
    - name: 'web.hook'
      webhook_configs:
      - url: 'http://127.0.0.1:5001/'
    
    - name: 'critical-alerts'
      email_configs:
      - to: 'ops@zkevm.example.com'
        subject: 'Critical Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}
      slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#alerts'
        title: 'Critical zkEVM Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
    
    - name: 'zkevm-alerts'
      slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#zkevm-alerts'
        title: 'zkEVM Performance Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}: {{ .Annotations.description }}{{ end }}'
EOF

    # Create Alertmanager Deployment
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alertmanager
  namespace: $MONITORING_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: alertmanager
  template:
    metadata:
      name: alertmanager
      labels:
        app: alertmanager
    spec:
      containers:
      - name: alertmanager
        image: prom/alertmanager:latest
        args:
          - '--config.file=/etc/alertmanager/config.yml'
          - '--storage.path=/alertmanager'
        ports:
        - name: alertmanager
          containerPort: 9093
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 200m
            memory: 256Mi
        volumeMounts:
        - name: config-volume
          mountPath: /etc/alertmanager
        - name: alertmanager
          mountPath: /alertmanager
      volumes:
      - name: config-volume
        configMap:
          name: alertmanager-config
      - name: alertmanager
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: alertmanager
  namespace: $MONITORING_NAMESPACE
spec:
  selector:
    app: alertmanager
  type: NodePort
  ports:
    - port: 9093
      targetPort: 9093
      nodePort: 30093
EOF

    log_success "Alertmanager setup completed"
}

# Create monitoring ingress
create_monitoring_ingress() {
    log_info "🌐 Creating monitoring ingress..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: monitoring-ingress
  namespace: $MONITORING_NAMESPACE
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: monitoring-auth
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required - zkEVM Monitoring'
spec:
  tls:
  - hosts:
    - grafana.zkevm.example.com
    - prometheus.zkevm.example.com
    - alerts.zkevm.example.com
    secretName: monitoring-tls
  rules:
  - host: grafana.zkevm.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: grafana
            port:
              number: 3000
  - host: prometheus.zkevm.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prometheus-service
            port:
              number: 8080
  - host: alerts.zkevm.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: alertmanager
            port:
              number: 9093
EOF

    log_success "Monitoring ingress created"
}

# Display access information
display_access_info() {
    log_success "🎉 Monitoring stack deployment completed!"
    echo
    log_info "📊 Access Information:"
    echo "  Grafana: http://$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):30030"
    echo "  Username: admin"
    echo "  Password: $GRAFANA_ADMIN_PASSWORD"
    echo
    echo "  Prometheus: http://$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):30090"
    echo "  Alertmanager: http://$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):30093"
    echo
    log_info "🔧 Configuration:"
    echo "  - zkEVM metrics are scraped every 5 seconds"
    echo "  - Prometheus retention: $PROMETHEUS_RETENTION"
    echo "  - Custom zkEVM dashboard pre-loaded in Grafana"
    echo "  - Alerts configured for proving performance, failures, and resource usage"
    echo
    log_warning "📝 Next Steps:"
    echo "  1. Configure Slack webhook URLs in Alertmanager config"
    echo "  2. Set up email SMTP settings for critical alerts"
    echo "  3. Review and customize alert thresholds"
    echo "  4. Configure ingress with proper DNS and TLS certificates"
}

# Main function
main() {
    log_info "🚀 Setting up ZODA-WARP zkEVM monitoring stack..."
    
    create_monitoring_namespace
    setup_prometheus
    setup_grafana
    setup_alertmanager
    create_monitoring_ingress
    
    # Wait for deployments to be ready
    log_info "⏳ Waiting for monitoring components to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/prometheus-server -n "$MONITORING_NAMESPACE"
    kubectl wait --for=condition=available --timeout=300s deployment/grafana -n "$MONITORING_NAMESPACE"
    kubectl wait --for=condition=available --timeout=300s deployment/alertmanager -n "$MONITORING_NAMESPACE"
    
    display_access_info
}

# Run if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
