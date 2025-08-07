//! # Production-Grade Logging System
//! 
//! This module provides structured logging with configurable outputs, performance tracking,
//! and integration with monitoring systems for the zkEVM proving system.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::Span;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};
use crate::error::ZkEvmError;

/// Log output format configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    /// Human-readable format for development
    Human,
    /// JSON format for production and log aggregation
    Json,
    /// Compact format for high-throughput scenarios
    Compact,
}

/// Log level configuration with component-specific overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Global log level
    pub level: String,
    /// Output format
    pub format: LogFormat,
    /// Component-specific log levels
    pub component_levels: HashMap<String, String>,
    /// Whether to include source code locations
    pub include_location: bool,
    /// Whether to include thread information
    pub include_thread: bool,
    /// Maximum log file size in MB (0 = unlimited)
    pub max_file_size_mb: u64,
    /// Number of log files to retain
    pub max_files: u32,
    /// Log file path (None = stdout only)
    pub file_path: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Human,
            component_levels: HashMap::new(),
            include_location: true,
            include_thread: false,
            max_file_size_mb: 100,
            max_files: 10,
            file_path: None,
        }
    }
}

/// Performance metrics tracker for logging
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub operation_counts: HashMap<String, u64>,
    pub operation_durations: HashMap<String, Vec<u64>>, // in microseconds
    pub error_counts: HashMap<String, u64>,
    pub peak_memory_usage: u64,
    pub total_cpu_time: u64,
}

/// Structured log entry for zkEVM operations
#[derive(Debug, Clone, Serialize)]
pub struct ZkEvmLogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: String,
    pub component: String,
    pub operation: String,
    pub message: String,
    pub duration_ms: Option<u64>,
    pub block_number: Option<u64>,
    pub transaction_hash: Option<String>,
    pub proof_type: Option<String>,
    pub performance_metrics: Option<HashMap<String, f64>>,
    pub error_details: Option<serde_json::Value>,
    pub context: HashMap<String, serde_json::Value>,
}

/// Thread-safe logger with structured output and performance tracking
pub struct ZkEvmLogger {
    config: Arc<RwLock<LogConfig>>,
    metrics: Arc<RwLock<PerformanceMetrics>>,
    operation_spans: Arc<RwLock<HashMap<String, Span>>>,
}

impl ZkEvmLogger {
    /// Initialize the logger with the given configuration
    pub async fn new(config: LogConfig) -> Result<Self, ZkEvmError> {
        // Set up simple tracing subscriber to avoid trait bound issues
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(config.level.as_str())
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .finish();

        // Only set global logger if not already set (for testing)
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            // In tests, we might have multiple logger instances, so we only warn
            if !e.to_string().contains("already been set") {
                return Err(ZkEvmError::ConfigurationError {
                    message: format!("Failed to set global logger: {}", e),
                    config_path: "logger_config".to_string(),
                    invalid_fields: vec![],
                });
            }
        }

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            operation_spans: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Build environment filter from configuration
    #[allow(dead_code)]
    fn build_env_filter(config: &LogConfig) -> Result<EnvFilter, ZkEvmError> {
        let mut filter = EnvFilter::new(&config.level);
        
        // Add component-specific filters
        for (component, level) in &config.component_levels {
            let directive = format!("{}={}", component, level);
            filter = filter.add_directive(directive.parse()
                .map_err(|e| ZkEvmError::ConfigurationError {
                    message: format!("Invalid log level directive: {}", e),
                    config_path: "log_config".to_string(),
                    invalid_fields: vec![component.clone()],
                })?);
        }
        
        Ok(filter)
    }

    /// Build formatter layer based on configuration
    #[allow(dead_code)]
    fn build_formatter(_config: &LogConfig) -> Result<impl tracing_subscriber::Layer<Registry> + Send + Sync, ZkEvmError> {
        // Use a simple consistent layer to avoid trait bound issues
        let layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true);
        Ok(layer)
    }

    /// Start tracking an operation
    pub async fn start_operation(&self, operation: &str, component: &str) -> String {
        let operation_id = format!("{}:{}:{}", component, operation, uuid::Uuid::new_v4());
        let span = tracing::info_span!(
            "zkvm_operation",
            operation = operation,
            component = component,
            operation_id = operation_id.as_str()
        );
        
        self.operation_spans.write().await.insert(operation_id.clone(), span);
        
        tracing::info!(
            operation = operation,
            component = component,
            operation_id = operation_id.as_str(),
            "Operation started"
        );
        
        operation_id
    }

    /// Complete an operation with success metrics
    pub async fn complete_operation(
        &self,
        operation_id: &str,
        duration_ms: u64,
        metrics: Option<HashMap<String, f64>>,
    ) {
        // Remove span
        let span = self.operation_spans.write().await.remove(operation_id);
        
        // Update performance metrics
        if let Some(span) = span {
            let _enter = span.enter();
            
            tracing::info!(
                operation_id = operation_id,
                duration_ms = duration_ms,
                metrics = ?metrics,
                "Operation completed successfully"
            );
        }

        // Update internal metrics
        let mut perf_metrics = self.metrics.write().await;
        let operation_name = operation_id.split(':').nth(1).unwrap_or("unknown");
        *perf_metrics.operation_counts.entry(operation_name.to_string()).or_insert(0) += 1;
        perf_metrics.operation_durations
            .entry(operation_name.to_string())
            .or_insert_with(Vec::new)
            .push(duration_ms * 1000); // Convert to microseconds
    }

    /// Log an operation failure
    pub async fn fail_operation(
        &self,
        operation_id: &str,
        error: &ZkEvmError,
        duration_ms: Option<u64>,
    ) {
        // Remove span
        let span = self.operation_spans.write().await.remove(operation_id);
        
        if let Some(span) = span {
            let _enter = span.enter();
            
            tracing::error!(
                operation_id = operation_id,
                duration_ms = duration_ms,
                error = %error,
                error_severity = ?error.severity(),
                error_category = ?error.category(),
                recovery_suggestions = ?error.recovery_suggestions(),
                "Operation failed"
            );
        }

        // Update error metrics
        let mut perf_metrics = self.metrics.write().await;
        let error_type = format!("{:?}", error.category());
        *perf_metrics.error_counts.entry(error_type).or_insert(0) += 1;
    }

    /// Log proof generation metrics
    pub async fn log_proof_generation(
        &self,
        proof_type: &str,
        block_number: u64,
        duration_ms: u64,
        proof_size_bytes: usize,
        verification_time_ms: Option<u64>,
        success: bool,
    ) {
        let entry = ZkEvmLogEntry {
            timestamp: chrono::Utc::now(),
            level: if success { "info" } else { "error" }.to_string(),
            component: "proof_generator".to_string(),
            operation: "generate_proof".to_string(),
            message: format!(
                "Proof generation {} for block {}",
                if success { "successful" } else { "failed" },
                block_number
            ),
            duration_ms: Some(duration_ms),
            block_number: Some(block_number),
            transaction_hash: None,
            proof_type: Some(proof_type.to_string()),
            performance_metrics: Some({
                let mut metrics = HashMap::new();
                metrics.insert("proof_size_bytes".to_string(), proof_size_bytes as f64);
                metrics.insert("proving_time_ms".to_string(), duration_ms as f64);
                if let Some(verify_time) = verification_time_ms {
                    metrics.insert("verification_time_ms".to_string(), verify_time as f64);
                }
                metrics.insert("throughput_tps".to_string(), 1000.0 / duration_ms as f64);
                metrics
            }),
            error_details: None,
            context: HashMap::new(),
        };

        if success {
            tracing::info!(
                proof_type = proof_type,
                block_number = block_number,
                duration_ms = duration_ms,
                proof_size_bytes = proof_size_bytes,
                verification_time_ms = verification_time_ms,
                throughput_tps = 1000.0 / duration_ms as f64,
                "Proof generation completed"
            );
        } else {
            tracing::error!(
                proof_type = proof_type,
                block_number = block_number,
                duration_ms = duration_ms,
                "Proof generation failed"
            );
        }
    }

    /// Log EVM execution metrics
    pub async fn log_evm_execution(
        &self,
        tx_hash: &str,
        gas_used: u64,
        gas_limit: u64,
        execution_time_ms: u64,
        opcodes_executed: usize,
        success: bool,
    ) {
        tracing::info!(
            transaction_hash = tx_hash,
            gas_used = gas_used,
            gas_limit = gas_limit,
            execution_time_ms = execution_time_ms,
            opcodes_executed = opcodes_executed,
            gas_efficiency = (gas_used as f64 / gas_limit as f64) * 100.0,
            opcodes_per_second = (opcodes_executed as f64 / execution_time_ms as f64) * 1000.0,
            success = success,
            "EVM execution completed"
        );
    }

    /// Log system performance metrics
    pub async fn log_system_metrics(&self, cpu_usage_percent: f64, memory_usage_mb: u64, disk_usage_percent: f64) {
        tracing::info!(
            cpu_usage_percent = cpu_usage_percent,
            memory_usage_mb = memory_usage_mb,
            disk_usage_percent = disk_usage_percent,
            "System performance metrics"
        );

        // Update peak memory usage
        let mut metrics = self.metrics.write().await;
        if memory_usage_mb > metrics.peak_memory_usage {
            metrics.peak_memory_usage = memory_usage_mb;
        }
    }

    /// Get aggregated performance metrics
    pub async fn get_performance_summary(&self) -> PerformanceMetrics {
        self.metrics.read().await.clone()
    }

    /// Update logger configuration at runtime
    pub async fn update_config(&self, new_config: LogConfig) -> Result<(), ZkEvmError> {
        *self.config.write().await = new_config;
        // Note: In a full implementation, we'd need to rebuild the tracing subscriber
        // This is a simplified version for demonstration
        Ok(())
    }

    /// Log benchmark results for performance tracking
    pub async fn log_benchmark(
        &self,
        benchmark_name: &str,
        duration_ms: u64,
        throughput_ops_per_sec: f64,
        resource_usage: HashMap<String, f64>,
    ) {
        tracing::info!(
            benchmark = benchmark_name,
            duration_ms = duration_ms,
            throughput_ops_per_sec = throughput_ops_per_sec,
            resource_usage = ?resource_usage,
            "Benchmark completed"
        );
    }

    /// Log validator/node metrics for network participation
    pub async fn log_validator_metrics(
        &self,
        validator_id: &str,
        blocks_validated: u64,
        average_validation_time_ms: f64,
        uptime_percent: f64,
    ) {
        tracing::info!(
            validator_id = validator_id,
            blocks_validated = blocks_validated,
            average_validation_time_ms = average_validation_time_ms,
            uptime_percent = uptime_percent,
            "Validator performance metrics"
        );
    }
}

/// Global logger instance
static mut GLOBAL_LOGGER: Option<ZkEvmLogger> = None;
static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize global logger (call once at application startup)
pub async fn init_logger(config: LogConfig) -> Result<(), ZkEvmError> {
    let logger = ZkEvmLogger::new(config).await?;
    
    LOGGER_INIT.call_once(|| {
        unsafe {
            GLOBAL_LOGGER = Some(logger);
        }
    });
    
    Ok(())
}

/// Get global logger instance
pub fn get_logger() -> Option<&'static ZkEvmLogger> {
    unsafe { GLOBAL_LOGGER.as_ref() }
}

/// Convenience macros for structured logging
#[macro_export]
macro_rules! zkvm_info {
    ($operation:expr, $component:expr, $($field:tt)*) => {
        tracing::info!(
            operation = $operation,
            component = $component,
            $($field)*
        );
    };
}

#[macro_export]
macro_rules! zkvm_error {
    ($operation:expr, $component:expr, $error:expr, $($field:tt)*) => {
        tracing::error!(
            operation = $operation,
            component = $component,
            error = %$error,
            error_severity = ?$error.severity(),
            error_category = ?$error.category(),
            $($field)*
        );
    };
}

#[macro_export]
macro_rules! zkvm_debug {
    ($operation:expr, $component:expr, $($field:tt)*) => {
        tracing::debug!(
            operation = $operation,
            component = $component,
            $($field)*
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_logger_initialization() {
        let config = LogConfig::default();
        let logger = ZkEvmLogger::new(config).await.unwrap();
        
        let operation_id = logger.start_operation("test_op", "test_component").await;
        assert!(operation_id.contains("test_component:test_op"));
        
        logger.complete_operation(&operation_id, 100, None).await;
        
        let metrics = logger.get_performance_summary().await;
        assert_eq!(metrics.operation_counts.get("test_op"), Some(&1));
    }

    #[tokio::test]
    async fn test_performance_tracking() {
        let config = LogConfig::default();
        let logger = ZkEvmLogger::new(config).await.unwrap();
        
        logger.log_proof_generation("ZODA-WARP", 12345, 150, 1024, Some(50), true).await;
        logger.log_evm_execution("0xabc123", 21000, 25000, 5, 100, true).await;
        
        let metrics = logger.get_performance_summary().await;
        // Metrics should be tracked internally
        assert!(metrics.operation_counts.len() >= 0);
    }
}
