// Monitoring and Metrics for Fractal Network
// Provides Prometheus-compatible metrics for production monitoring

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Metrics collector for fractal network
pub struct FractalMetrics {
    // Proof metrics
    pub total_proofs_generated: AtomicU64,
    pub total_proofs_failed: AtomicU64,
    pub total_proving_time_ms: AtomicU64,
    
    // Task metrics
    pub tasks_submitted: AtomicU64,
    pub tasks_claimed: AtomicU64,
    pub tasks_completed: AtomicU64,
    pub tasks_expired: AtomicU64,
    
    // Economic metrics
    pub total_rewards_earned: AtomicU64,
    pub total_rewards_paid: AtomicU64,
    
    // Network metrics
    pub active_provers: AtomicU64,
    pub active_peers: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    
    // Performance metrics
    pub avg_proof_time_ms: AtomicU64,
    pub min_proof_time_ms: AtomicU64,
    pub max_proof_time_ms: AtomicU64,
    
    // Node uptime
    start_time: Instant,
}

impl FractalMetrics {
    pub fn new() -> Self {
        Self {
            total_proofs_generated: AtomicU64::new(0),
            total_proofs_failed: AtomicU64::new(0),
            total_proving_time_ms: AtomicU64::new(0),
            tasks_submitted: AtomicU64::new(0),
            tasks_claimed: AtomicU64::new(0),
            tasks_completed: AtomicU64::new(0),
            tasks_expired: AtomicU64::new(0),
            total_rewards_earned: AtomicU64::new(0),
            total_rewards_paid: AtomicU64::new(0),
            active_provers: AtomicU64::new(0),
            active_peers: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            avg_proof_time_ms: AtomicU64::new(0),
            min_proof_time_ms: AtomicU64::new(u64::MAX),
            max_proof_time_ms: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
    
    /// Record a successful proof
    pub fn record_proof_success(&self, duration_ms: u64) {
        self.total_proofs_generated.fetch_add(1, Ordering::Relaxed);
        self.total_proving_time_ms.fetch_add(duration_ms, Ordering::Relaxed);
        
        // Update min/max
        let current_min = self.min_proof_time_ms.load(Ordering::Relaxed);
        if duration_ms < current_min {
            self.min_proof_time_ms.store(duration_ms, Ordering::Relaxed);
        }
        
        let current_max = self.max_proof_time_ms.load(Ordering::Relaxed);
        if duration_ms > current_max {
            self.max_proof_time_ms.store(duration_ms, Ordering::Relaxed);
        }
        
        // Update average
        let total_proofs = self.total_proofs_generated.load(Ordering::Relaxed);
        let total_time = self.total_proving_time_ms.load(Ordering::Relaxed);
        if total_proofs > 0 {
            self.avg_proof_time_ms.store(total_time / total_proofs, Ordering::Relaxed);
        }
    }
    
    /// Record a failed proof
    pub fn record_proof_failure(&self) {
        self.total_proofs_failed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record task submission
    pub fn record_task_submitted(&self) {
        self.tasks_submitted.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record task claim
    pub fn record_task_claimed(&self) {
        self.tasks_claimed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record task completion
    pub fn record_task_completed(&self) {
        self.tasks_completed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record reward earned
    pub fn record_reward_earned(&self, amount: u64) {
        self.total_rewards_earned.fetch_add(amount, Ordering::Relaxed);
    }
    
    /// Update active provers count
    pub fn set_active_provers(&self, count: u64) {
        self.active_provers.store(count, Ordering::Relaxed);
    }
    
    /// Update active peers count
    pub fn set_active_peers(&self, count: u64) {
        self.active_peers.store(count, Ordering::Relaxed);
    }
    
    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
    
    /// Export metrics in Prometheus format
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Proof metrics
        output.push_str("# HELP fractal_proofs_generated_total Total number of proofs generated\n");
        output.push_str("# TYPE fractal_proofs_generated_total counter\n");
        output.push_str(&format!("fractal_proofs_generated_total {}\n", 
            self.total_proofs_generated.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_proofs_failed_total Total number of failed proofs\n");
        output.push_str("# TYPE fractal_proofs_failed_total counter\n");
        output.push_str(&format!("fractal_proofs_failed_total {}\n", 
            self.total_proofs_failed.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_proof_time_avg_ms Average proof generation time in milliseconds\n");
        output.push_str("# TYPE fractal_proof_time_avg_ms gauge\n");
        output.push_str(&format!("fractal_proof_time_avg_ms {}\n", 
            self.avg_proof_time_ms.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_proof_time_min_ms Minimum proof generation time in milliseconds\n");
        output.push_str("# TYPE fractal_proof_time_min_ms gauge\n");
        output.push_str(&format!("fractal_proof_time_min_ms {}\n", 
            self.min_proof_time_ms.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_proof_time_max_ms Maximum proof generation time in milliseconds\n");
        output.push_str("# TYPE fractal_proof_time_max_ms gauge\n");
        output.push_str(&format!("fractal_proof_time_max_ms {}\n", 
            self.max_proof_time_ms.load(Ordering::Relaxed)));
        
        // Task metrics
        output.push_str("# HELP fractal_tasks_submitted_total Total tasks submitted\n");
        output.push_str("# TYPE fractal_tasks_submitted_total counter\n");
        output.push_str(&format!("fractal_tasks_submitted_total {}\n", 
            self.tasks_submitted.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_tasks_claimed_total Total tasks claimed\n");
        output.push_str("# TYPE fractal_tasks_claimed_total counter\n");
        output.push_str(&format!("fractal_tasks_claimed_total {}\n", 
            self.tasks_claimed.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_tasks_completed_total Total tasks completed\n");
        output.push_str("# TYPE fractal_tasks_completed_total counter\n");
        output.push_str(&format!("fractal_tasks_completed_total {}\n", 
            self.tasks_completed.load(Ordering::Relaxed)));
        
        // Economic metrics
        output.push_str("# HELP fractal_rewards_earned_total Total rewards earned\n");
        output.push_str("# TYPE fractal_rewards_earned_total counter\n");
        output.push_str(&format!("fractal_rewards_earned_total {}\n", 
            self.total_rewards_earned.load(Ordering::Relaxed)));
        
        // Network metrics
        output.push_str("# HELP fractal_active_provers Number of active provers\n");
        output.push_str("# TYPE fractal_active_provers gauge\n");
        output.push_str(&format!("fractal_active_provers {}\n", 
            self.active_provers.load(Ordering::Relaxed)));
        
        output.push_str("# HELP fractal_active_peers Number of active P2P peers\n");
        output.push_str("# TYPE fractal_active_peers gauge\n");
        output.push_str(&format!("fractal_active_peers {}\n", 
            self.active_peers.load(Ordering::Relaxed)));
        
        // Uptime
        output.push_str("# HELP fractal_uptime_seconds Node uptime in seconds\n");
        output.push_str("# TYPE fractal_uptime_seconds counter\n");
        output.push_str(&format!("fractal_uptime_seconds {}\n", self.uptime_seconds()));
        
        output
    }
    
    /// Export metrics as JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "proofs": {
                "total_generated": self.total_proofs_generated.load(Ordering::Relaxed),
                "total_failed": self.total_proofs_failed.load(Ordering::Relaxed),
                "avg_time_ms": self.avg_proof_time_ms.load(Ordering::Relaxed),
                "min_time_ms": self.min_proof_time_ms.load(Ordering::Relaxed),
                "max_time_ms": self.max_proof_time_ms.load(Ordering::Relaxed),
            },
            "tasks": {
                "submitted": self.tasks_submitted.load(Ordering::Relaxed),
                "claimed": self.tasks_claimed.load(Ordering::Relaxed),
                "completed": self.tasks_completed.load(Ordering::Relaxed),
                "expired": self.tasks_expired.load(Ordering::Relaxed),
            },
            "economics": {
                "total_earned": self.total_rewards_earned.load(Ordering::Relaxed),
                "total_paid": self.total_rewards_paid.load(Ordering::Relaxed),
            },
            "network": {
                "active_provers": self.active_provers.load(Ordering::Relaxed),
                "active_peers": self.active_peers.load(Ordering::Relaxed),
                "messages_sent": self.messages_sent.load(Ordering::Relaxed),
                "messages_received": self.messages_received.load(Ordering::Relaxed),
            },
            "uptime_seconds": self.uptime_seconds(),
        })
    }
}

impl Default for FractalMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP server for metrics endpoint
pub async fn start_metrics_server(
    metrics: Arc<FractalMetrics>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use warp::Filter;
    
    let metrics_clone = metrics.clone();
    let prometheus_route = warp::path("metrics")
        .map(move || {
            let body = metrics_clone.to_prometheus();
            warp::reply::with_header(body, "Content-Type", "text/plain; version=0.0.4")
        });
    
    let metrics_clone = metrics.clone();
    let json_route = warp::path("metrics.json")
        .map(move || {
            warp::reply::json(&metrics_clone.to_json())
        });
    
    let health_route = warp::path("health")
        .map(|| warp::reply::json(&serde_json::json!({"status": "healthy"})));
    
    let routes = prometheus_route
        .or(json_route)
        .or(health_route);
    
    println!("📊 Metrics server starting on http://0.0.0.0:{}", port);
    println!("   Prometheus: http://localhost:{}/metrics", port);
    println!("   JSON: http://localhost:{}/metrics.json", port);
    println!("   Health: http://localhost:{}/health", port);
    
    warp::serve(routes)
        .run(([0, 0, 0, 0], port))
        .await;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_recording() {
        let metrics = FractalMetrics::new();
        
        metrics.record_proof_success(100);
        metrics.record_proof_success(200);
        metrics.record_proof_failure();
        
        assert_eq!(metrics.total_proofs_generated.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.total_proofs_failed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.avg_proof_time_ms.load(Ordering::Relaxed), 150);
        assert_eq!(metrics.min_proof_time_ms.load(Ordering::Relaxed), 100);
        assert_eq!(metrics.max_proof_time_ms.load(Ordering::Relaxed), 200);
    }
    
    #[test]
    fn test_prometheus_export() {
        let metrics = FractalMetrics::new();
        metrics.record_proof_success(100);
        
        let prometheus = metrics.to_prometheus();
        assert!(prometheus.contains("fractal_proofs_generated_total 1"));
        assert!(prometheus.contains("fractal_proof_time_avg_ms 100"));
    }
    
    #[test]
    fn test_json_export() {
        let metrics = FractalMetrics::new();
        metrics.record_proof_success(150);
        metrics.record_task_submitted();
        
        let json = metrics.to_json();
        assert_eq!(json["proofs"]["total_generated"], 1);
        assert_eq!(json["tasks"]["submitted"], 1);
    }
}
