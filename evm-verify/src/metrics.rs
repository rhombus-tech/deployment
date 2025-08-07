//! # Production-Grade Metrics Collection System
//! 
//! This module provides comprehensive metrics collection, monitoring, and alerting
//! for the zkEVM proving system with Prometheus-compatible exports.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use crate::error::{ZkEvmError, ErrorSeverity};

/// Metric types for different kinds of measurements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    /// Monotonically increasing counter
    Counter,
    /// Value that can go up and down
    Gauge,
    /// Histogram for tracking distributions
    Histogram,
    /// Summary with quantiles
    Summary,
}

/// Individual metric value with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub value: f64,
    pub timestamp: u64,
    pub labels: HashMap<String, String>,
}

/// Histogram bucket for tracking value distributions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    pub upper_bound: f64,
    pub count: u64,
}

/// Histogram metric with configurable buckets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    pub buckets: Vec<HistogramBucket>,
    pub count: u64,
    pub sum: f64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let histogram_buckets = buckets
            .into_iter()
            .map(|upper_bound| HistogramBucket { upper_bound, count: 0 })
            .collect();
        
        Self {
            buckets: histogram_buckets,
            count: 0,
            sum: 0.0,
        }
    }

    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        
        for bucket in &mut self.buckets {
            if value <= bucket.upper_bound {
                bucket.count += 1;
            }
        }
    }

    pub fn percentile(&self, p: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        
        let target_count = (self.count as f64 * p / 100.0).ceil() as u64;
        
        // Buckets already contain cumulative counts
        for bucket in &self.buckets {
            if bucket.count >= target_count {
                return bucket.upper_bound;
            }
        }
        
        self.buckets.last().map_or(0.0, |b| b.upper_bound)
    }
}

/// Core metrics for the zkEVM proving system
#[derive(Debug, Clone)]
pub struct ZkEvmMetrics {
    // Proof generation metrics
    pub proofs_generated_total: Arc<AtomicU64>,
    pub proof_generation_duration_seconds: Arc<RwLock<Histogram>>,
    pub proof_verification_duration_seconds: Arc<RwLock<Histogram>>,
    pub proof_size_bytes: Arc<RwLock<Histogram>>,
    
    // EVM execution metrics
    pub transactions_processed_total: Arc<AtomicU64>,
    pub evm_execution_duration_seconds: Arc<RwLock<Histogram>>,
    pub gas_used_total: Arc<AtomicU64>,
    pub opcodes_executed_total: Arc<AtomicU64>,
    
    // Error metrics
    pub errors_total: Arc<RwLock<HashMap<String, AtomicU64>>>,
    pub error_rate_by_severity: Arc<RwLock<HashMap<ErrorSeverity, AtomicU64>>>,
    
    // System performance metrics
    pub cpu_usage_percent: Arc<RwLock<f64>>,
    pub memory_usage_bytes: Arc<AtomicU64>,
    pub disk_usage_percent: Arc<RwLock<f64>>,
    pub network_bytes_sent: Arc<AtomicU64>,
    pub network_bytes_received: Arc<AtomicU64>,
    
    // Throughput metrics
    pub transactions_per_second: Arc<RwLock<f64>>,
    pub blocks_processed_per_hour: Arc<RwLock<f64>>,
    pub average_block_processing_time: Arc<RwLock<f64>>,
    
    // Queue and backlog metrics
    pub pending_transactions: Arc<AtomicUsize>,
    pub pending_proofs: Arc<AtomicUsize>,
    pub backlog_size: Arc<AtomicUsize>,
    
    // Validator metrics
    pub validator_uptime_seconds: Arc<AtomicU64>,
    pub blocks_validated_total: Arc<AtomicU64>,
    pub validation_success_rate: Arc<RwLock<f64>>,
    
    // Custom metrics for specific use cases
    pub custom_metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
}

impl Default for ZkEvmMetrics {
    fn default() -> Self {
        Self {
            proofs_generated_total: Arc::new(AtomicU64::new(0)),
            proof_generation_duration_seconds: Arc::new(RwLock::new(Histogram::new(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
            ]))),
            proof_verification_duration_seconds: Arc::new(RwLock::new(Histogram::new(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5
            ]))),
            proof_size_bytes: Arc::new(RwLock::new(Histogram::new(vec![
                100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 500000.0
            ]))),
            transactions_processed_total: Arc::new(AtomicU64::new(0)),
            evm_execution_duration_seconds: Arc::new(RwLock::new(Histogram::new(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5
            ]))),
            gas_used_total: Arc::new(AtomicU64::new(0)),
            opcodes_executed_total: Arc::new(AtomicU64::new(0)),
            errors_total: Arc::new(RwLock::new(HashMap::new())),
            error_rate_by_severity: Arc::new(RwLock::new(HashMap::new())),
            cpu_usage_percent: Arc::new(RwLock::new(0.0)),
            memory_usage_bytes: Arc::new(AtomicU64::new(0)),
            disk_usage_percent: Arc::new(RwLock::new(0.0)),
            network_bytes_sent: Arc::new(AtomicU64::new(0)),
            network_bytes_received: Arc::new(AtomicU64::new(0)),
            transactions_per_second: Arc::new(RwLock::new(0.0)),
            blocks_processed_per_hour: Arc::new(RwLock::new(0.0)),
            average_block_processing_time: Arc::new(RwLock::new(0.0)),
            pending_transactions: Arc::new(AtomicUsize::new(0)),
            pending_proofs: Arc::new(AtomicUsize::new(0)),
            backlog_size: Arc::new(AtomicUsize::new(0)),
            validator_uptime_seconds: Arc::new(AtomicU64::new(0)),
            blocks_validated_total: Arc::new(AtomicU64::new(0)),
            validation_success_rate: Arc::new(RwLock::new(100.0)),
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl ZkEvmMetrics {
    /// Create a new ZkEvmMetrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful proof generation
    pub async fn record_proof_generation(&self, duration: Duration, proof_size: usize, proof_type: &str) {
        self.proofs_generated_total.fetch_add(1, Ordering::Relaxed);
        
        let duration_seconds = duration.as_secs_f64();
        self.proof_generation_duration_seconds.write().await.observe(duration_seconds);
        self.proof_size_bytes.write().await.observe(proof_size as f64);
        
        // Update custom metric for proof type
        let proof_type_key = format!("proofs_generated_by_type_{}", proof_type.to_lowercase());
        let mut custom = self.custom_metrics.write().await;
        let current_count = custom.get(&proof_type_key)
            .map(|v| v.value as u64)
            .unwrap_or(0) + 1;
        
        custom.insert(proof_type_key, MetricValue {
            value: current_count as f64,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            labels: HashMap::from([("proof_type".to_string(), proof_type.to_string())]),
        });
    }

    /// Record a successful proof verification
    pub async fn record_proof_verification(&self, duration: Duration, success: bool) {
        let duration_seconds = duration.as_secs_f64();
        self.proof_verification_duration_seconds.write().await.observe(duration_seconds);
        
        // Track verification success rate
        let success_key = if success { "verification_success" } else { "verification_failure" };
        let mut custom = self.custom_metrics.write().await;
        let current_count = custom.get(success_key)
            .map(|v| v.value as u64)
            .unwrap_or(0) + 1;
        
        custom.insert(success_key.to_string(), MetricValue {
            value: current_count as f64,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            labels: HashMap::from([("result".to_string(), success.to_string())]),
        });
    }

    /// Record EVM transaction execution
    pub async fn record_transaction_execution(&self, duration: Duration, gas_used: u64, opcodes: usize) {
        self.transactions_processed_total.fetch_add(1, Ordering::Relaxed);
        self.gas_used_total.fetch_add(gas_used, Ordering::Relaxed);
        self.opcodes_executed_total.fetch_add(opcodes as u64, Ordering::Relaxed);
        
        let duration_seconds = duration.as_secs_f64();
        self.evm_execution_duration_seconds.write().await.observe(duration_seconds);
    }

    /// Record an error occurrence
    pub async fn record_error(&self, error: &ZkEvmError) {
        let error_category = format!("{:?}", error.category());
        let error_severity = error.severity();
        
        // Update error count by category
        let mut errors = self.errors_total.write().await;
        errors.entry(error_category.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        
        // Update error count by severity
        {
            let mut severity_errors = self.error_rate_by_severity.write().await;
            if !severity_errors.contains_key(&error_severity) {
                severity_errors.insert(error_severity.clone(), AtomicU64::new(0));
            }
            if let Some(counter) = severity_errors.get(&error_severity) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Update system resource usage
    pub async fn update_system_metrics(&self, cpu_percent: f64, memory_bytes: u64, disk_percent: f64) {
        *self.cpu_usage_percent.write().await = cpu_percent;
        self.memory_usage_bytes.store(memory_bytes, Ordering::Relaxed);
        *self.disk_usage_percent.write().await = disk_percent;
    }

    /// Update throughput metrics
    pub async fn update_throughput_metrics(&self, tps: f64, blocks_per_hour: f64, avg_block_time: f64) {
        *self.transactions_per_second.write().await = tps;
        *self.blocks_processed_per_hour.write().await = blocks_per_hour;
        *self.average_block_processing_time.write().await = avg_block_time;
    }

    /// Update queue metrics
    pub fn update_queue_metrics(&self, pending_txs: usize, pending_proofs: usize, backlog: usize) {
        self.pending_transactions.store(pending_txs, Ordering::Relaxed);
        self.pending_proofs.store(pending_proofs, Ordering::Relaxed);
        self.backlog_size.store(backlog, Ordering::Relaxed);
    }

    /// Record validator performance
    pub async fn record_validator_metrics(&self, uptime_seconds: u64, blocks_validated: u64, success_rate: f64) {
        self.validator_uptime_seconds.store(uptime_seconds, Ordering::Relaxed);
        self.blocks_validated_total.store(blocks_validated, Ordering::Relaxed);
        *self.validation_success_rate.write().await = success_rate;
    }

    /// Add custom metric
    pub async fn set_custom_metric(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let mut custom = self.custom_metrics.write().await;
        custom.insert(name.to_string(), MetricValue {
            value,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            labels,
        });
    }

    /// Get Prometheus-compatible metrics export
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Counter metrics
        output.push_str(&format!("# HELP zkvm_proofs_generated_total Total number of proofs generated\n"));
        output.push_str(&format!("# TYPE zkvm_proofs_generated_total counter\n"));
        output.push_str(&format!("zkvm_proofs_generated_total {}\n", 
            self.proofs_generated_total.load(Ordering::Relaxed)));
        
        output.push_str(&format!("# HELP zkvm_transactions_processed_total Total number of transactions processed\n"));
        output.push_str(&format!("# TYPE zkvm_transactions_processed_total counter\n"));
        output.push_str(&format!("zkvm_transactions_processed_total {}\n", 
            self.transactions_processed_total.load(Ordering::Relaxed)));
        
        output.push_str(&format!("# HELP zkvm_gas_used_total Total gas used in transaction execution\n"));
        output.push_str(&format!("# TYPE zkvm_gas_used_total counter\n"));
        output.push_str(&format!("zkvm_gas_used_total {}\n", 
            self.gas_used_total.load(Ordering::Relaxed)));
        
        // Gauge metrics
        output.push_str(&format!("# HELP zkvm_cpu_usage_percent Current CPU usage percentage\n"));
        output.push_str(&format!("# TYPE zkvm_cpu_usage_percent gauge\n"));
        output.push_str(&format!("zkvm_cpu_usage_percent {}\n", 
            *self.cpu_usage_percent.read().await));
        
        output.push_str(&format!("# HELP zkvm_memory_usage_bytes Current memory usage in bytes\n"));
        output.push_str(&format!("# TYPE zkvm_memory_usage_bytes gauge\n"));
        output.push_str(&format!("zkvm_memory_usage_bytes {}\n", 
            self.memory_usage_bytes.load(Ordering::Relaxed)));
        
        output.push_str(&format!("# HELP zkvm_transactions_per_second Current transaction processing rate\n"));
        output.push_str(&format!("# TYPE zkvm_transactions_per_second gauge\n"));
        output.push_str(&format!("zkvm_transactions_per_second {}\n", 
            *self.transactions_per_second.read().await));
        
        // Histogram metrics
        let proof_duration_hist = self.proof_generation_duration_seconds.read().await;
        output.push_str(&format!("# HELP zkvm_proof_generation_duration_seconds Time spent generating proofs\n"));
        output.push_str(&format!("# TYPE zkvm_proof_generation_duration_seconds histogram\n"));
        for bucket in &proof_duration_hist.buckets {
            output.push_str(&format!("zkvm_proof_generation_duration_seconds_bucket{{le=\"{}\"}} {}\n", 
                bucket.upper_bound, bucket.count));
        }
        output.push_str(&format!("zkvm_proof_generation_duration_seconds_count {}\n", proof_duration_hist.count));
        output.push_str(&format!("zkvm_proof_generation_duration_seconds_sum {}\n", proof_duration_hist.sum));
        
        // Error metrics by category
        let errors = self.errors_total.read().await;
        for (category, count) in errors.iter() {
            output.push_str(&format!("# HELP zkvm_errors_total Total number of errors by category\n"));
            output.push_str(&format!("# TYPE zkvm_errors_total counter\n"));
            output.push_str(&format!("zkvm_errors_total{{category=\"{}\"}} {}\n", 
                category, count.load(Ordering::Relaxed)));
        }
        
        // Custom metrics
        let custom = self.custom_metrics.read().await;
        for (name, metric) in custom.iter() {
            output.push_str(&format!("# HELP zkvm_{} Custom metric\n", name));
            output.push_str(&format!("# TYPE zkvm_{} gauge\n", name));
            let labels = metric.labels.iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect::<Vec<_>>()
                .join(",");
            output.push_str(&format!("zkvm_{}{{{}}} {}\n", name, labels, metric.value));
        }
        
        output
    }

    /// Get comprehensive performance summary
    pub async fn get_performance_summary(&self) -> PerformanceSummary {
        let proof_hist = self.proof_generation_duration_seconds.read().await;
        let verification_hist = self.proof_verification_duration_seconds.read().await;
        let execution_hist = self.evm_execution_duration_seconds.read().await;
        
        PerformanceSummary {
            proofs_generated: self.proofs_generated_total.load(Ordering::Relaxed),
            transactions_processed: self.transactions_processed_total.load(Ordering::Relaxed),
            total_gas_used: self.gas_used_total.load(Ordering::Relaxed),
            average_proof_time_ms: if proof_hist.count > 0 { 
                (proof_hist.sum / proof_hist.count as f64) * 1000.0 
            } else { 0.0 },
            p95_proof_time_ms: proof_hist.percentile(95.0) * 1000.0,
            p99_proof_time_ms: proof_hist.percentile(99.0) * 1000.0,
            average_verification_time_ms: if verification_hist.count > 0 { 
                (verification_hist.sum / verification_hist.count as f64) * 1000.0 
            } else { 0.0 },
            average_execution_time_ms: if execution_hist.count > 0 { 
                (execution_hist.sum / execution_hist.count as f64) * 1000.0 
            } else { 0.0 },
            current_tps: *self.transactions_per_second.read().await,
            current_cpu_usage: *self.cpu_usage_percent.read().await,
            current_memory_mb: self.memory_usage_bytes.load(Ordering::Relaxed) / 1024 / 1024,
            pending_work_items: self.pending_transactions.load(Ordering::Relaxed) + 
                               self.pending_proofs.load(Ordering::Relaxed),
        }
    }
}

/// Performance summary for reporting and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub proofs_generated: u64,
    pub transactions_processed: u64,
    pub total_gas_used: u64,
    pub average_proof_time_ms: f64,
    pub p95_proof_time_ms: f64,
    pub p99_proof_time_ms: f64,
    pub average_verification_time_ms: f64,
    pub average_execution_time_ms: f64,
    pub current_tps: f64,
    pub current_cpu_usage: f64,
    pub current_memory_mb: u64,
    pub pending_work_items: usize,
}

/// Global metrics instance
static mut GLOBAL_METRICS: Option<ZkEvmMetrics> = None;
static METRICS_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize global metrics (call once at application startup)
pub fn init_metrics() -> &'static ZkEvmMetrics {
    METRICS_INIT.call_once(|| {
        unsafe {
            GLOBAL_METRICS = Some(ZkEvmMetrics::default());
        }
    });
    
    unsafe { GLOBAL_METRICS.as_ref().unwrap() }
}

/// Get global metrics instance
pub fn get_metrics() -> &'static ZkEvmMetrics {
    unsafe { 
        GLOBAL_METRICS.as_ref().expect("Metrics not initialized. Call init_metrics() first.")
    }
}

/// Convenience macros for metrics recording
#[macro_export]
macro_rules! record_proof_metric {
    ($duration:expr, $size:expr, $proof_type:expr) => {
        if let Some(metrics) = get_metrics() {
            tokio::spawn(async move {
                metrics.record_proof_generation($duration, $size, $proof_type).await;
            });
        }
    };
}

#[macro_export]
macro_rules! record_error_metric {
    ($error:expr) => {
        if let Some(metrics) = get_metrics() {
            tokio::spawn(async move {
                metrics.record_error($error).await;
            });
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_histogram_functionality() {
        let mut hist = Histogram::new(vec![0.1, 0.5, 1.0, 5.0]);
        hist.observe(0.05); // ≤ 0.1,0.5,1.0,5.0 → all buckets +1
        hist.observe(0.3);  // ≤ 0.5,1.0,5.0 → last 3 buckets +1
        hist.observe(0.8);  // ≤ 1.0,5.0 → last 2 buckets +1
        hist.observe(2.0);  // ≤ 5.0 → last bucket +1
        
        assert_eq!(hist.count, 4);
        assert_eq!(hist.sum, 3.15);
        
        // Verify cumulative bucket counts
        assert_eq!(hist.buckets[0].count, 1); // 0.1 bucket: 1 value (0.05)
        assert_eq!(hist.buckets[1].count, 2); // 0.5 bucket: 2 values (0.05, 0.3)
        assert_eq!(hist.buckets[2].count, 3); // 1.0 bucket: 3 values (0.05, 0.3, 0.8)
        assert_eq!(hist.buckets[3].count, 4); // 5.0 bucket: 4 values (all)
        
        // 50th percentile: 50% of 4 = 2, first bucket with count ≥ 2 is 0.5
        assert_eq!(hist.percentile(50.0), 0.5);
        // 90th percentile: 90% of 4 = 3.6, ceil = 4, first bucket with count ≥ 4 is 5.0
        assert_eq!(hist.percentile(90.0), 5.0);
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let metrics = ZkEvmMetrics::default();
        
        metrics.record_proof_generation(Duration::from_millis(100), 1024, "ZODA").await;
        metrics.record_transaction_execution(Duration::from_millis(5), 21000, 50).await;
        
        assert_eq!(metrics.proofs_generated_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.transactions_processed_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.gas_used_total.load(Ordering::Relaxed), 21000);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let metrics = ZkEvmMetrics::default();
        metrics.record_proof_generation(Duration::from_millis(100), 1024, "ZODA").await;
        
        let prometheus_output = metrics.export_prometheus().await;
        assert!(prometheus_output.contains("zkvm_proofs_generated_total 1"));
        assert!(prometheus_output.contains("# HELP"));
        assert!(prometheus_output.contains("# TYPE"));
    }

    #[tokio::test]
    async fn test_performance_summary() {
        let metrics = ZkEvmMetrics::default();
        metrics.record_proof_generation(Duration::from_millis(100), 1024, "ZODA").await;
        metrics.record_proof_generation(Duration::from_millis(200), 2048, "WARP").await;
        metrics.update_throughput_metrics(1000.0, 100.0, 150.0).await;
        
        let summary = metrics.get_performance_summary().await;
        assert_eq!(summary.proofs_generated, 2);
        assert_eq!(summary.current_tps, 1000.0);
        // Use approximate comparison for floating point values
        assert!((summary.average_proof_time_ms - 150.0).abs() < 1e-9); // (100 + 200) / 2
    }
}
