// ZODA Production Metrics Collection System
//
// Comprehensive metrics for monitoring, alerting, and performance analysis

use std::time::{Duration, Instant};
use std::sync::Arc;
use prometheus::{
    Counter, Histogram, Gauge, IntCounter, IntGauge, 
    register_counter, register_histogram, register_gauge, 
    register_int_counter, register_int_gauge,
    HistogramOpts, Opts
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Comprehensive metrics collection for ZODA-WARP system
#[derive(Clone)]
pub struct ZodaMetrics {
    // =================================
    // THROUGHPUT AND VOLUME METRICS
    // =================================
    
    /// Total number of circuits processed successfully
    pub circuits_processed_total: IntCounter,
    
    /// Total number of proofs generated
    pub proofs_generated_total: IntCounter,
    
    /// Total number of verifications completed
    pub verifications_completed_total: IntCounter,
    
    /// Total number of tensor operations performed
    pub tensor_operations_total: IntCounter,
    
    /// Total number of mainnet blocks analyzed
    pub mainnet_blocks_analyzed_total: IntCounter,

    // =================================
    // PERFORMANCE METRICS
    // =================================
    
    /// Time spent proving circuits (seconds)
    pub proving_duration_seconds: Histogram,
    
    /// Time spent verifying proofs (seconds)
    pub verification_duration_seconds: Histogram,
    
    /// Time spent on tensor operations (microseconds)
    pub tensor_operation_duration_micros: Histogram,
    
    /// Time spent on Reed-Solomon operations (microseconds)
    pub reed_solomon_duration_micros: Histogram,
    
    /// End-to-end circuit processing latency (milliseconds)
    pub circuit_processing_latency_ms: Histogram,

    // =================================
    // QUALITY AND CORRECTNESS METRICS
    // =================================
    
    /// Current syndrome validation success rate (0.0-1.0)
    pub syndrome_success_rate: Gauge,
    
    /// Current compression ratio achieved
    pub compression_ratio: Gauge,
    
    /// Percentage of proofs meeting Ethereum size limit
    pub ethereum_compliance_rate: Gauge,
    
    /// Average proof quality score (0.0-1.0)
    pub proof_quality_score: Gauge,

    // =================================
    // SIZE AND EFFICIENCY METRICS
    // =================================
    
    /// Generated proof size in bytes
    pub proof_size_bytes: Histogram,
    
    /// Verifying key size in bytes
    pub verifying_key_size_bytes: Histogram,
    
    /// Circuit bytecode size in bytes
    pub circuit_bytecode_size_bytes: Histogram,
    
    /// Memory usage during proving (MB)
    pub proving_memory_usage_mb: Histogram,

    // =================================
    // ERROR AND RELIABILITY METRICS
    // =================================
    
    /// Total number of errors by type
    pub errors_total: IntCounter,
    
    /// Number of retry attempts
    pub retry_attempts_total: IntCounter,
    
    /// Number of successful recoveries after errors
    pub error_recoveries_total: IntCounter,
    
    /// Current error rate (errors per second)
    pub error_rate: Gauge,

    // =================================
    // RESOURCE UTILIZATION METRICS
    // =================================
    
    /// Current memory usage in bytes
    pub memory_usage_bytes: IntGauge,
    
    /// Current CPU usage percentage (0.0-100.0)
    pub cpu_usage_percent: Gauge,
    
    /// Number of active worker threads
    pub active_worker_threads: IntGauge,
    
    /// Cache hit rate percentage
    pub cache_hit_rate_percent: Gauge,

    // =================================
    // NETWORK AND RPC METRICS
    // =================================
    
    /// Total RPC requests made
    pub rpc_requests_total: IntCounter,
    
    /// RPC request duration (milliseconds)
    pub rpc_request_duration_ms: Histogram,
    
    /// Number of RPC failures
    pub rpc_failures_total: IntCounter,
    
    /// Current RPC connection status (0=disconnected, 1=connected)
    pub rpc_connection_status: IntGauge,

    // =================================
    // BUSINESS AND OPERATIONAL METRICS
    // =================================
    
    /// Estimated proving cost in USD (for cost tracking)
    pub proving_cost_usd: Gauge,
    
    /// Validator count using ZODA-WARP
    pub validator_count: IntGauge,
    
    /// Total gas costs saved through efficient proving
    pub gas_costs_saved_total: Counter,
    
    /// System uptime seconds
    pub uptime_seconds: IntGauge,
}

impl ZodaMetrics {
    /// Create new metrics instance with all collectors registered
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            // Throughput metrics
            circuits_processed_total: register_int_counter!(
                "zoda_circuits_processed_total",
                "Total number of circuits processed successfully"
            )?,
            
            proofs_generated_total: register_int_counter!(
                "zoda_proofs_generated_total", 
                "Total number of proofs generated"
            )?,
            
            verifications_completed_total: register_int_counter!(
                "zoda_verifications_completed_total",
                "Total number of verifications completed"
            )?,
            
            tensor_operations_total: register_int_counter!(
                "zoda_tensor_operations_total",
                "Total number of tensor operations performed"
            )?,
            
            mainnet_blocks_analyzed_total: register_int_counter!(
                "zoda_mainnet_blocks_analyzed_total",
                "Total number of mainnet blocks analyzed"
            )?,

            // Performance metrics
            proving_duration_seconds: register_histogram!(
                HistogramOpts::new(
                    "zoda_proving_duration_seconds",
                    "Time spent proving circuits in seconds"
                ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0])
            )?,
            
            verification_duration_seconds: register_histogram!(
                HistogramOpts::new(
                    "zoda_verification_duration_seconds", 
                    "Time spent verifying proofs in seconds"
                ).buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1])
            )?,
            
            tensor_operation_duration_micros: register_histogram!(
                HistogramOpts::new(
                    "zoda_tensor_operation_duration_microseconds",
                    "Time spent on tensor operations in microseconds"
                ).buckets(vec![10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0])
            )?,
            
            reed_solomon_duration_micros: register_histogram!(
                HistogramOpts::new(
                    "zoda_reed_solomon_duration_microseconds",
                    "Time spent on Reed-Solomon operations in microseconds"
                ).buckets(vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0])
            )?,
            
            circuit_processing_latency_ms: register_histogram!(
                HistogramOpts::new(
                    "zoda_circuit_processing_latency_milliseconds",
                    "End-to-end circuit processing latency in milliseconds"
                ).buckets(vec![1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0])
            )?,

            // Quality metrics
            syndrome_success_rate: register_gauge!(
                "zoda_syndrome_success_rate",
                "Current syndrome validation success rate (0.0-1.0)"
            )?,
            
            compression_ratio: register_gauge!(
                "zoda_compression_ratio", 
                "Current compression ratio achieved"
            )?,
            
            ethereum_compliance_rate: register_gauge!(
                "zoda_ethereum_compliance_rate",
                "Percentage of proofs meeting Ethereum size limit"
            )?,
            
            proof_quality_score: register_gauge!(
                "zoda_proof_quality_score",
                "Average proof quality score (0.0-1.0)"
            )?,

            // Size metrics
            proof_size_bytes: register_histogram!(
                HistogramOpts::new(
                    "zoda_proof_size_bytes",
                    "Generated proof size in bytes"
                ).buckets(vec![1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 200000.0, 300000.0])
            )?,
            
            verifying_key_size_bytes: register_histogram!(
                HistogramOpts::new(
                    "zoda_verifying_key_size_bytes",
                    "Verifying key size in bytes"
                ).buckets(vec![100.0, 500.0, 1000.0, 5000.0, 10000.0])
            )?,
            
            circuit_bytecode_size_bytes: register_histogram!(
                HistogramOpts::new(
                    "zoda_circuit_bytecode_size_bytes",
                    "Circuit bytecode size in bytes"
                ).buckets(vec![1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0])
            )?,
            
            proving_memory_usage_mb: register_histogram!(
                HistogramOpts::new(
                    "zoda_proving_memory_usage_mb",
                    "Memory usage during proving in MB"
                ).buckets(vec![10.0, 50.0, 100.0, 500.0, 1000.0, 2000.0, 4000.0])
            )?,

            // Error metrics
            errors_total: register_int_counter!(
                "zoda_errors_total",
                "Total number of errors by type"
            )?,
            
            retry_attempts_total: register_int_counter!(
                "zoda_retry_attempts_total",
                "Number of retry attempts"
            )?,
            
            error_recoveries_total: register_int_counter!(
                "zoda_error_recoveries_total",
                "Number of successful recoveries after errors"
            )?,
            
            error_rate: register_gauge!(
                "zoda_error_rate",
                "Current error rate (errors per second)"
            )?,

            // Resource metrics
            memory_usage_bytes: register_int_gauge!(
                "zoda_memory_usage_bytes",
                "Current memory usage in bytes"
            )?,
            
            cpu_usage_percent: register_gauge!(
                "zoda_cpu_usage_percent",
                "Current CPU usage percentage (0.0-100.0)"
            )?,
            
            active_worker_threads: register_int_gauge!(
                "zoda_active_worker_threads",
                "Number of active worker threads"
            )?,
            
            cache_hit_rate_percent: register_gauge!(
                "zoda_cache_hit_rate_percent",
                "Cache hit rate percentage"
            )?,

            // Network metrics
            rpc_requests_total: register_int_counter!(
                "zoda_rpc_requests_total",
                "Total RPC requests made"
            )?,
            
            rpc_request_duration_ms: register_histogram!(
                HistogramOpts::new(
                    "zoda_rpc_request_duration_milliseconds",
                    "RPC request duration in milliseconds"
                ).buckets(vec![10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0])
            )?,
            
            rpc_failures_total: register_int_counter!(
                "zoda_rpc_failures_total",
                "Number of RPC failures"
            )?,
            
            rpc_connection_status: register_int_gauge!(
                "zoda_rpc_connection_status",
                "Current RPC connection status (0=disconnected, 1=connected)"
            )?,

            // Business metrics
            proving_cost_usd: register_gauge!(
                "zoda_proving_cost_usd",
                "Estimated proving cost in USD (for cost tracking)"
            )?,
            
            validator_count: register_int_gauge!(
                "zoda_validator_count",
                "Validator count using ZODA-WARP"
            )?,
            
            gas_costs_saved_total: register_counter!(
                "zoda_gas_costs_saved_total",
                "Total gas costs saved through efficient proving"
            )?,
            
            uptime_seconds: register_int_gauge!(
                "zoda_uptime_seconds",
                "System uptime in seconds"
            )?,
        })
    }

    /// Record successful circuit processing with comprehensive metrics
    pub fn record_circuit_processing(
        &self,
        proving_duration: Duration,
        proof_size: usize,
        verifying_key_size: usize,
        bytecode_size: usize,
        syndrome_rate: f64,
        compression_ratio: f64,
        memory_usage_mb: usize,
    ) {
        // Increment counters
        self.circuits_processed_total.inc();
        self.proofs_generated_total.inc();
        
        // Record timing
        self.proving_duration_seconds.observe(proving_duration.as_secs_f64());
        self.circuit_processing_latency_ms.observe(proving_duration.as_millis() as f64);
        
        // Record sizes
        self.proof_size_bytes.observe(proof_size as f64);
        self.verifying_key_size_bytes.observe(verifying_key_size as f64);
        self.circuit_bytecode_size_bytes.observe(bytecode_size as f64);
        self.proving_memory_usage_mb.observe(memory_usage_mb as f64);
        
        // Record quality metrics
        self.syndrome_success_rate.set(syndrome_rate);
        self.compression_ratio.set(compression_ratio);
        
        // Check Ethereum compliance (300KB limit)
        let is_compliant = proof_size <= 300_000;
        self.ethereum_compliance_rate.set(if is_compliant { 1.0 } else { 0.0 });
        
        // Calculate proof quality score (composite metric)
        let quality_score = (syndrome_rate * 0.4) + 
                          (compression_ratio.min(10.0) / 10.0 * 0.3) +
                          (if is_compliant { 1.0 } else { 0.0 } * 0.3);
        self.proof_quality_score.set(quality_score);
    }

    /// Record tensor operation performance
    pub fn record_tensor_operation(&self, operation_type: &str, duration: Duration) {
        self.tensor_operations_total.inc();
        self.tensor_operation_duration_micros.observe(duration.as_micros() as f64);
    }

    /// Record Reed-Solomon operation performance
    pub fn record_reed_solomon_operation(&self, duration: Duration) {
        self.reed_solomon_duration_micros.observe(duration.as_micros() as f64);
    }

    /// Record verification operation
    pub fn record_verification(&self, duration: Duration, success: bool) {
        self.verifications_completed_total.inc();
        self.verification_duration_seconds.observe(duration.as_secs_f64());
        
        if success {
            // Verification successful - update quality metrics positively
            self.proof_quality_score.set(self.proof_quality_score.get() * 1.01);
        }
    }

    /// Record error occurrence with recovery attempt
    pub fn record_error(&self, error_type: &str, recovery_attempted: bool, recovery_success: bool) {
        self.errors_total.inc();
        
        if recovery_attempted {
            self.retry_attempts_total.inc();
            
            if recovery_success {
                self.error_recoveries_total.inc();
            }
        }
        
        // Update error rate (simple calculation - could be more sophisticated)
        let total_operations = self.circuits_processed_total.get() as f64;
        let total_errors = self.errors_total.get() as f64;
        let error_rate = if total_operations > 0.0 { 
            total_errors / total_operations 
        } else { 
            0.0 
        };
        self.error_rate.set(error_rate);
    }

    /// Record RPC operation
    pub fn record_rpc_operation(&self, duration: Duration, success: bool) {
        self.rpc_requests_total.inc();
        self.rpc_request_duration_ms.observe(duration.as_millis() as f64);
        
        if !success {
            self.rpc_failures_total.inc();
        }
        
        // Update connection status
        self.rpc_connection_status.set(if success { 1 } else { 0 });
    }

    /// Update resource usage metrics
    pub fn update_resource_usage(
        &self, 
        memory_bytes: u64, 
        cpu_percent: f64, 
        active_threads: i64,
        cache_hit_rate: f64
    ) {
        self.memory_usage_bytes.set(memory_bytes as i64);
        self.cpu_usage_percent.set(cpu_percent);
        self.active_worker_threads.set(active_threads);
        self.cache_hit_rate_percent.set(cache_hit_rate * 100.0);
    }

    /// Record mainnet block analysis
    pub fn record_mainnet_analysis(&self, block_number: u64) {
        self.mainnet_blocks_analyzed_total.inc();
    }

    /// Update business metrics
    pub fn update_business_metrics(&self, validator_count: i64, cost_savings: f64) {
        self.validator_count.set(validator_count);
        self.gas_costs_saved_total.inc_by(cost_savings);
    }

    /// Get current system health score (0.0-1.0)
    pub fn get_health_score(&self) -> f64 {
        let syndrome_score = self.syndrome_success_rate.get();
        let compliance_score = self.ethereum_compliance_rate.get();
        let error_score = 1.0 - self.error_rate.get().min(1.0);
        let quality_score = self.proof_quality_score.get();
        
        (syndrome_score * 0.3 + compliance_score * 0.3 + error_score * 0.2 + quality_score * 0.2)
    }
    
    /// Generate performance summary report
    pub fn generate_performance_summary(&self) -> PerformanceSummary {
        PerformanceSummary {
            circuits_processed: self.circuits_processed_total.get(),
            proofs_generated: self.proofs_generated_total.get(),
            verifications_completed: self.verifications_completed_total.get(),
            syndrome_success_rate: self.syndrome_success_rate.get(),
            compression_ratio: self.compression_ratio.get(),
            ethereum_compliance_rate: self.ethereum_compliance_rate.get(),
            error_rate: self.error_rate.get(),
            health_score: self.get_health_score(),
            uptime_seconds: self.uptime_seconds.get(),
        }
    }
}

/// Performance summary for reporting and dashboards
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PerformanceSummary {
    pub circuits_processed: u64,
    pub proofs_generated: u64,
    pub verifications_completed: u64,
    pub syndrome_success_rate: f64,
    pub compression_ratio: f64,
    pub ethereum_compliance_rate: f64,
    pub error_rate: f64,
    pub health_score: f64,
    pub uptime_seconds: i64,
}

/// Background metrics collection task
pub struct MetricsCollector {
    metrics: Arc<ZodaMetrics>,
    collection_interval: Duration,
    start_time: Instant,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new(metrics: Arc<ZodaMetrics>, collection_interval: Duration) -> Self {
        Self {
            metrics,
            collection_interval,
            start_time: Instant::now(),
        }
    }
    
    /// Start background metrics collection
    pub async fn start_collection(&self) {
        let mut interval = tokio::time::interval(self.collection_interval);
        
        loop {
            interval.tick().await;
            self.collect_system_metrics().await;
        }
    }
    
    /// Collect system-level metrics
    async fn collect_system_metrics(&self) {
        // Update uptime
        let uptime = self.start_time.elapsed().as_secs() as i64;
        self.metrics.uptime_seconds.set(uptime);
        
        // Collect memory usage
        if let Ok(mem_info) = sys_info::mem_info() {
            let used_memory = (mem_info.total - mem_info.free) * 1024; // Convert to bytes
            self.metrics.memory_usage_bytes.set(used_memory as i64);
        }
        
        // Collect CPU usage (simplified - in production use proper system monitoring)
        if let Ok(loadavg) = sys_info::loadavg() {
            let cpu_percent = loadavg.one * 100.0 / num_cpus::get() as f64;
            self.metrics.cpu_usage_percent.set(cpu_percent);
        }
        
        // Update active thread count (approximate)
        let thread_count = std::thread::available_parallelism()
            .map(|n| n.get() as i64)
            .unwrap_or(1);
        self.metrics.active_worker_threads.set(thread_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_metrics_creation() {
        let metrics = ZodaMetrics::new().unwrap();
        assert_eq!(metrics.circuits_processed_total.get(), 0);
    }
    
    #[test]
    fn test_circuit_processing_recording() {
        let metrics = ZodaMetrics::new().unwrap();
        
        metrics.record_circuit_processing(
            Duration::from_millis(100),
            50000,  // 50KB proof
            2000,   // 2KB key
            100000, // 100KB bytecode
            0.95,   // 95% syndrome success
            4.5,    // 4.5x compression
            256,    // 256MB memory
        );
        
        assert_eq!(metrics.circuits_processed_total.get(), 1);
        assert_eq!(metrics.proofs_generated_total.get(), 1);
        assert_eq!(metrics.syndrome_success_rate.get(), 0.95);
        assert!(metrics.get_health_score() > 0.8);
    }
    
    #[test]
    fn test_error_recording() {
        let metrics = ZodaMetrics::new().unwrap();
        
        metrics.record_error("TestError", true, true);
        
        assert_eq!(metrics.errors_total.get(), 1);
        assert_eq!(metrics.retry_attempts_total.get(), 1);
        assert_eq!(metrics.error_recoveries_total.get(), 1);
    }
}
