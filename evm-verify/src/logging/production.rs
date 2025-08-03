// ZODA Production Logging System
//
// Comprehensive structured logging with tracing for production deployment

use std::time::{Duration, Instant};
use std::any::type_name;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug, instrument, Level};
use tracing_subscriber::{
    layer::SubscriberExt, 
    util::SubscriberInitExt, 
    fmt::format::FmtSpan,
    EnvFilter
};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

/// Log output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogOutput {
    /// Human-readable console output for development
    Console,
    /// Structured JSON output for production monitoring
    Json,
    /// File-based logging with rotation
    File { 
        directory: String, 
        rotation: LogRotation 
    },
    /// Combined console + file output
    Combined {
        console_format: LogFormat,
        file_directory: String,
        rotation: LogRotation,
    },
}

/// Log format configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Human,
    Json,
    Compact,
}

/// Log file rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogRotation {
    Hourly,
    Daily,
    Never,
}

/// Environment-specific logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub output: LogOutput,
    pub enable_spans: bool,
    pub enable_targets: bool,
    pub filter_modules: Vec<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            output: LogOutput::Console,
            enable_spans: true,
            enable_targets: true,
            filter_modules: vec![
                "zoda".to_string(),
                "evm_verify".to_string(),
            ],
        }
    }
}

/// Initialize production logging system
pub fn init_production_logging(config: &LogConfig) -> Result<(), Box<dyn std::error::Error>> {
    let level_filter = match config.level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG, 
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    // Build environment filter
    let mut filter = EnvFilter::new("")
        .add_directive(level_filter.into());
    
    // Add module-specific filters
    for module in &config.filter_modules {
        filter = filter.add_directive(format!("{}={}", module, config.level).parse()?);
    }

    let span_events = if config.enable_spans {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    match &config.output {
        LogOutput::Console => {
            tracing_subscriber::fmt()
                .pretty()
                .with_max_level(level_filter)
                .with_env_filter(filter)
                .with_span_events(span_events)
                .with_target(config.enable_targets)
                .init();
        }

        LogOutput::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_max_level(level_filter)
                .with_env_filter(filter)
                .with_span_events(span_events)
                .with_target(config.enable_targets)
                .init();
        }

        LogOutput::File { directory, rotation } => {
            let rotation = match rotation {
                LogRotation::Hourly => Rotation::HOURLY,
                LogRotation::Daily => Rotation::DAILY,
                LogRotation::Never => Rotation::NEVER,
            };

            let file_appender = RollingFileAppender::new(rotation, directory, "zoda.log");

            tracing_subscriber::fmt()
                .json()
                .with_max_level(level_filter)
                .with_env_filter(filter)
                .with_span_events(span_events)
                .with_target(config.enable_targets)
                .with_writer(file_appender)
                .init();
        }

        LogOutput::Combined { console_format, file_directory, rotation } => {
            let rotation = match rotation {
                LogRotation::Hourly => Rotation::HOURLY,
                LogRotation::Daily => Rotation::DAILY,
                LogRotation::Never => Rotation::NEVER,
            };

            let file_appender = RollingFileAppender::new(rotation, file_directory, "zoda.log");

            // Use registry for multiple layers
            let registry = tracing_subscriber::registry()
                .with(filter.clone())
                .with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_span_events(span_events)
                        .with_target(config.enable_targets)
                );

            match console_format {
                LogFormat::Human => {
                    registry
                        .with(
                            tracing_subscriber::fmt::layer()
                                .json()
                                .with_span_events(span_events)
                                .with_target(config.enable_targets)
                                .with_writer(file_appender)
                        )
                        .init();
                }
                LogFormat::Json => {
                    registry
                        .with(
                            tracing_subscriber::fmt::layer()
                                .json()
                                .with_span_events(span_events)
                                .with_target(config.enable_targets)
                                .with_writer(file_appender)
                        )
                        .init();
                }
                LogFormat::Compact => {
                    registry
                        .with(
                            tracing_subscriber::fmt::layer()
                                .compact()
                                .with_span_events(span_events)
                                .with_target(config.enable_targets)
                                .with_writer(file_appender)
                        )
                        .init();
                }
            }
        }
    }

    info!("ZODA logging system initialized");
    info!("Log level: {}", config.level);
    info!("Output format: {:?}", config.output);

    Ok(())
}

/// Structured logging utilities for ZODA operations
pub struct ZodaLogger;

impl ZodaLogger {
    /// Log circuit accumulation with performance metrics
    #[instrument(skip(operation), fields(circuit_type = type_name::<F>()))]
    pub async fn log_circuit_operation<F, T, E>(
        operation_name: &str,
        circuit_size: usize,
        operation: F,
    ) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let start = Instant::now();
        
        info!(
            "Starting {} operation",
            operation_name,
            circuit_size = circuit_size,
        );

        match operation.await {
            Ok(result) => {
                let duration = start.elapsed();
                info!(
                    "{} operation successful",
                    operation_name,
                    duration_ms = duration.as_millis(),
                    circuit_size = circuit_size,
                );
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                error!(
                    "{} operation failed",
                    operation_name,
                    error = %e,
                    duration_ms = duration.as_millis(),
                    circuit_size = circuit_size,
                );
                Err(e)
            }
        }
    }

    /// Log tensor operations with compression metrics
    #[instrument(skip(operation))]
    pub fn log_tensor_operation<F, T, E>(
        operation_name: &str,
        tensor_dimensions: (usize, usize),
        operation: F,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: std::fmt::Display,
    {
        let start = Instant::now();
        
        debug!(
            "Starting tensor {} operation",
            operation_name,
            tensor_rows = tensor_dimensions.0,
            tensor_cols = tensor_dimensions.1,
        );

        match operation() {
            Ok(result) => {
                let duration = start.elapsed();
                debug!(
                    "Tensor {} operation successful",
                    operation_name,
                    duration_us = duration.as_micros(),
                    tensor_rows = tensor_dimensions.0,
                    tensor_cols = tensor_dimensions.1,
                );
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!(
                    "Tensor {} operation failed",
                    operation_name,
                    error = %e,
                    duration_us = duration.as_micros(),
                    tensor_rows = tensor_dimensions.0,
                    tensor_cols = tensor_dimensions.1,
                );
                Err(e)
            }
        }
    }

    /// Log proof generation with size and compression metrics
    #[instrument(skip(operation))]
    pub fn log_proof_generation<F, T, E>(
        proof_type: &str,
        expected_size_kb: usize,
        operation: F,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: std::fmt::Display,
    {
        let start = Instant::now();
        
        info!(
            "Generating {} proof",
            proof_type,
            expected_size_kb = expected_size_kb,
        );

        match operation() {
            Ok(result) => {
                let duration = start.elapsed();
                info!(
                    "{} proof generation successful",
                    proof_type,
                    generation_time_ms = duration.as_millis(),
                    expected_size_kb = expected_size_kb,
                );
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                error!(
                    "{} proof generation failed",
                    proof_type,
                    error = %e,
                    generation_time_ms = duration.as_millis(),
                    expected_size_kb = expected_size_kb,
                );
                Err(e)
            }
        }
    }

    /// Log network operations with endpoint and timing
    #[instrument(skip(operation))]
    pub async fn log_network_operation<F, T, E>(
        operation_name: &str,
        endpoint: &str,
        timeout: Duration,
        operation: F,
    ) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let start = Instant::now();
        
        debug!(
            "Starting {} network operation",
            operation_name,
            endpoint = endpoint,
            timeout_ms = timeout.as_millis(),
        );

        match operation.await {
            Ok(result) => {
                let duration = start.elapsed();
                debug!(
                    "{} network operation successful",
                    operation_name,
                    endpoint = endpoint,
                    duration_ms = duration.as_millis(),
                );
                Ok(result)
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!(
                    "{} network operation failed",
                    operation_name,
                    endpoint = endpoint,
                    error = %e,
                    duration_ms = duration.as_millis(),
                );
                Err(e)
            }
        }
    }

    /// Log system resource usage
    pub fn log_resource_usage(
        operation: &str,
        memory_mb: usize,
        cpu_percent: f64,
        duration: Duration,
    ) {
        info!(
            "Resource usage for {}",
            operation,
            memory_mb = memory_mb,
            cpu_percent = cpu_percent,
            duration_ms = duration.as_millis(),
        );
    }

    /// Log error with recovery strategy
    pub fn log_error_with_recovery(
        error: &crate::errors::production::ZodaError,
        recovery_attempted: bool,
        recovery_successful: Option<bool>,
    ) {
        let severity = error.severity();
        let is_retryable = error.is_retryable();

        match severity {
            crate::errors::production::ErrorSeverity::Critical => {
                error!(
                    "Critical error occurred",
                    error = %error,
                    severity = %severity,
                    retryable = is_retryable,
                    recovery_attempted = recovery_attempted,
                    recovery_successful = recovery_successful,
                );
            }
            crate::errors::production::ErrorSeverity::High => {
                error!(
                    "High severity error",
                    error = %error,
                    severity = %severity,
                    retryable = is_retryable,
                    recovery_attempted = recovery_attempted,
                    recovery_successful = recovery_successful,
                );
            }
            crate::errors::production::ErrorSeverity::Medium => {
                warn!(
                    "Medium severity error",
                    error = %error,
                    severity = %severity,
                    retryable = is_retryable,
                    recovery_attempted = recovery_attempted,
                    recovery_successful = recovery_successful,
                );
            }
            crate::errors::production::ErrorSeverity::Low => {
                info!(
                    "Low severity error",
                    error = %error,
                    severity = %severity,
                    retryable = is_retryable,
                    recovery_attempted = recovery_attempted,
                    recovery_successful = recovery_successful,
                );
            }
        }
    }
}

/// Create environment-specific log configurations
pub fn create_log_config_for_env(environment: &str) -> LogConfig {
    match environment {
        "production" => LogConfig {
            level: "info".to_string(),
            output: LogOutput::Combined {
                console_format: LogFormat::Json,
                file_directory: "/var/log/zoda".to_string(),
                rotation: LogRotation::Hourly,
            },
            enable_spans: false, // Reduce overhead in production
            enable_targets: true,
            filter_modules: vec![
                "zoda".to_string(),
                "evm_verify".to_string(),
                "warp".to_string(),
            ],
        },

        "staging" => LogConfig {
            level: "debug".to_string(),
            output: LogOutput::Combined {
                console_format: LogFormat::Human,
                file_directory: "./logs".to_string(),
                rotation: LogRotation::Daily,
            },
            enable_spans: true,
            enable_targets: true,
            filter_modules: vec![
                "zoda".to_string(),
                "evm_verify".to_string(),
                "warp".to_string(),
            ],
        },

        "development" => LogConfig {
            level: "trace".to_string(),
            output: LogOutput::Console,
            enable_spans: true,
            enable_targets: true,
            filter_modules: vec![
                "zoda".to_string(),
                "evm_verify".to_string(),
                "warp".to_string(),
            ],
        },

        _ => LogConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_circuit_operation_logging() {
        let config = create_log_config_for_env("development");
        init_production_logging(&config).unwrap();

        let result = ZodaLogger::log_circuit_operation(
            "test_accumulation",
            1024,
            async { Ok::<_, String>("success".to_string()) }
        ).await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_tensor_operation_logging() {
        let config = create_log_config_for_env("development");
        init_production_logging(&config).unwrap();

        let result = ZodaLogger::log_tensor_operation(
            "matrix_multiply",
            (32, 16),
            || Ok::<_, String>("success".to_string())
        );

        assert!(result.is_ok());
    }
}
