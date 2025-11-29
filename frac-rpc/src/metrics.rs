use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default)]
pub struct MetricsData {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_latency_ms: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

pub struct MetricsCollector {
    data: Arc<RwLock<MetricsData>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MetricsData::default())),
        }
    }

    pub async fn record_request(&self, duration: std::time::Duration, success: bool) {
        let mut data = self.data.write().await;
        data.total_requests += 1;
        data.total_latency_ms += duration.as_millis() as f64;

        if success {
            data.successful_requests += 1;
        } else {
            data.failed_requests += 1;
        }
    }

    pub async fn record_cache_hit(&self) {
        let mut data = self.data.write().await;
        data.cache_hits += 1;
    }

    pub async fn record_cache_miss(&self) {
        let mut data = self.data.write().await;
        data.cache_misses += 1;
    }

    pub async fn export_prometheus(&self) -> String {
        let data = self.data.read().await;
        let avg_latency = if data.total_requests > 0 {
            data.total_latency_ms / data.total_requests as f64
        } else {
            0.0
        };

        format!(
            r#"# HELP frac_rpc_requests_total Total number of RPC requests
# TYPE frac_rpc_requests_total counter
frac_rpc_requests_total {}

# HELP frac_rpc_requests_successful Successful RPC requests
# TYPE frac_rpc_requests_successful counter
frac_rpc_requests_successful {}

# HELP frac_rpc_requests_failed Failed RPC requests
# TYPE frac_rpc_requests_failed counter
frac_rpc_requests_failed {}

# HELP frac_rpc_latency_avg_ms Average request latency in milliseconds
# TYPE frac_rpc_latency_avg_ms gauge
frac_rpc_latency_avg_ms {:.2}

# HELP frac_rpc_cache_hits Cache hits
# TYPE frac_rpc_cache_hits counter
frac_rpc_cache_hits {}

# HELP frac_rpc_cache_misses Cache misses
# TYPE frac_rpc_cache_misses counter
frac_rpc_cache_misses {}
"#,
            data.total_requests,
            data.successful_requests,
            data.failed_requests,
            avg_latency,
            data.cache_hits,
            data.cache_misses
        )
    }
}
