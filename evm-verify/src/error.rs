//! # Production-Grade Error Handling System
//! 
//! This module provides comprehensive error handling for the zkEVM proving system,
//! with detailed error categorization, recovery strategies, and monitoring integration.

use thiserror::Error;
use serde::{Deserialize, Serialize};

/// Critical error severity levels for monitoring and alerting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ErrorSeverity {
    /// System is down or critically compromised
    Critical,
    /// Feature degradation or performance issues
    High,
    /// Minor issues that don't affect core functionality
    Medium,
    /// Informational warnings
    Low,
}

/// Error categories for structured error handling and recovery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Cryptographic proof generation/verification failures
    Cryptographic,
    /// EVM execution and bytecode processing errors
    EVMExecution,
    /// Network and I/O related errors
    Network,
    /// Configuration and environment setup issues
    Configuration,
    /// Resource exhaustion (memory, disk, CPU)
    Resource,
    /// Data corruption or invalid input
    DataIntegrity,
    /// Performance degradation beyond acceptable thresholds
    Performance,
    /// External dependency failures
    External,
}

/// Comprehensive error type for the zkEVM proving system
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ZkEvmError {
    /// Cryptographic proof generation failed
    #[error("Cryptographic proof generation failed: {message} (details: {details})")]
    ProofGenerationFailed {
        message: String,
        details: String,
        proof_type: String,
        block_number: Option<u64>,
    },

    /// Cryptographic proof verification failed
    #[error("Cryptographic proof verification failed: {message} (proof_size: {proof_size} bytes)")]
    ProofVerificationFailed {
        message: String,
        proof_size: usize,
        expected_hash: Option<String>,
        actual_hash: Option<String>,
    },

    /// EVM execution trace generation failed
    #[error("EVM execution trace generation failed: {message} (bytecode_len: {bytecode_len})")]
    ExecutionTraceFailed {
        message: String,
        bytecode_len: usize,
        gas_limit: u64,
        opcode: Option<String>,
    },

    /// Circuit synthesis or constraint generation failed
    #[error("Circuit synthesis failed: {message} (constraints: {constraint_count})")]
    CircuitSynthesisFailed {
        message: String,
        constraint_count: usize,
        variable_count: Option<usize>,
    },

    /// Network communication or blockchain RPC errors
    #[error("Network error: {message} (endpoint: {endpoint})")]
    NetworkError {
        message: String,
        endpoint: String,
        retry_count: usize,
    },

    /// Configuration validation or loading errors
    #[error("Configuration error: {message} (config_path: {config_path})")]
    ConfigurationError {
        message: String,
        config_path: String,
        invalid_fields: Vec<String>,
    },

    /// Resource exhaustion errors
    #[error("Resource exhaustion: {resource_type} (current: {current_usage}, limit: {limit})")]
    ResourceExhaustion {
        resource_type: String,
        current_usage: u64,
        limit: u64,
        suggestion: String,
    },

    /// Data integrity or validation errors
    #[error("Data integrity error: {message} (data_type: {data_type})")]
    DataIntegrityError {
        message: String,
        data_type: String,
        checksum_expected: Option<String>,
        checksum_actual: Option<String>,
    },

    /// Performance degradation beyond acceptable thresholds
    #[error("Performance degradation: {metric} = {value} (threshold: {threshold})")]
    PerformanceDegradation {
        metric: String,
        value: f64,
        threshold: f64,
        duration_ms: u64,
    },

    /// External dependency failures
    #[error("External dependency failed: {service} - {message}")]
    ExternalDependencyFailed {
        service: String,
        message: String,
        status_code: Option<u16>,
        last_success: Option<chrono::DateTime<chrono::Utc>>,
    },

    /// Validation failed with details
    #[error("Validation failed: {message} (severity: {severity:?})")]
    ValidationFailed {
        message: String,
        severity: ErrorSeverity,
    },

    /// Processing operation failed
    #[error("Processing failed: {message} (severity: {severity:?})")]
    ProcessingFailed {
        message: String,
        severity: ErrorSeverity,
    },

    /// Generic internal error with context
    #[error("Internal error: {message} (context: {context})")]
    InternalError {
        message: String,
        context: String,
        stack_trace: Option<String>,
    },
}

impl ZkEvmError {
    /// Get the severity level for this error
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ZkEvmError::ProofGenerationFailed { .. } => ErrorSeverity::Critical,
            ZkEvmError::ProofVerificationFailed { .. } => ErrorSeverity::Critical,
            ZkEvmError::ResourceExhaustion { .. } => ErrorSeverity::High,
            ZkEvmError::NetworkError { retry_count, .. } => {
                if *retry_count > 3 { ErrorSeverity::High } else { ErrorSeverity::Medium }
            },
            ZkEvmError::PerformanceDegradation { .. } => ErrorSeverity::Medium,
            ZkEvmError::ConfigurationError { .. } => ErrorSeverity::High,
            ZkEvmError::DataIntegrityError { .. } => ErrorSeverity::High,
            ZkEvmError::ExternalDependencyFailed { .. } => ErrorSeverity::Medium,
            ZkEvmError::ValidationFailed { severity, .. } => severity.clone(),
            ZkEvmError::ProcessingFailed { severity, .. } => severity.clone(),
            ZkEvmError::ExecutionTraceFailed { .. } => ErrorSeverity::High,
            ZkEvmError::CircuitSynthesisFailed { .. } => ErrorSeverity::High,
            ZkEvmError::InternalError { .. } => ErrorSeverity::Critical,
        }
    }

    /// Get the category for this error
    pub fn category(&self) -> ErrorCategory {
        match self {
            ZkEvmError::ProofGenerationFailed { .. } => ErrorCategory::Cryptographic,
            ZkEvmError::ProofVerificationFailed { .. } => ErrorCategory::Cryptographic,
            ZkEvmError::ExecutionTraceFailed { .. } => ErrorCategory::EVMExecution,
            ZkEvmError::CircuitSynthesisFailed { .. } => ErrorCategory::Cryptographic,
            ZkEvmError::NetworkError { .. } => ErrorCategory::Network,
            ZkEvmError::ConfigurationError { .. } => ErrorCategory::Configuration,
            ZkEvmError::ResourceExhaustion { .. } => ErrorCategory::Resource,
            ZkEvmError::DataIntegrityError { .. } => ErrorCategory::DataIntegrity,
            ZkEvmError::PerformanceDegradation { .. } => ErrorCategory::Performance,
            ZkEvmError::ValidationFailed { .. } => ErrorCategory::DataIntegrity,
            ZkEvmError::ProcessingFailed { .. } => ErrorCategory::EVMExecution,
            ZkEvmError::ExternalDependencyFailed { .. } => ErrorCategory::External,
            ZkEvmError::InternalError { .. } => ErrorCategory::Configuration,
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            ZkEvmError::NetworkError { retry_count, .. } => *retry_count < 5,
            ZkEvmError::ExternalDependencyFailed { .. } => true,
            ZkEvmError::ResourceExhaustion { .. } => false, // Need to address resource issue first
            ZkEvmError::ConfigurationError { .. } => false,
            ZkEvmError::DataIntegrityError { .. } => false,
            _ => false, // Cryptographic and execution errors are typically not retryable
        }
    }

    /// Get recovery suggestions for this error
    pub fn recovery_suggestions(&self) -> Vec<String> {
        match self {
            ZkEvmError::ResourceExhaustion { resource_type, suggestion, .. } => {
                vec![
                    suggestion.clone(),
                    format!("Monitor {} usage more closely", resource_type),
                    "Consider scaling up resources or optimizing algorithms".to_string(),
                ]
            },
            ZkEvmError::NetworkError { .. } => vec![
                "Check network connectivity".to_string(),
                "Verify endpoint availability".to_string(),
                "Consider exponential backoff retry strategy".to_string(),
            ],
            ZkEvmError::ConfigurationError { invalid_fields, .. } => {
                let mut suggestions = vec!["Review configuration file syntax".to_string()];
                if !invalid_fields.is_empty() {
                    suggestions.push(format!("Fix invalid fields: {}", invalid_fields.join(", ")));
                }
                suggestions.push("Validate against configuration schema".to_string());
                suggestions
            },
            ZkEvmError::PerformanceDegradation { metric, threshold, .. } => vec![
                format!("Investigate {} performance bottlenecks", metric),
                format!("Consider optimizing to meet {} threshold", threshold),
                "Review system resource utilization".to_string(),
                "Check for memory leaks or inefficient algorithms".to_string(),
            ],
            ZkEvmError::ProofGenerationFailed { .. } => vec![
                "Verify input data integrity".to_string(),
                "Check cryptographic parameter setup".to_string(),
                "Review system resource availability".to_string(),
                "Consider reducing proof complexity if possible".to_string(),
            ],
            _ => vec!["Contact system administrator".to_string()],
        }
    }

    /// Convert error to structured log entry
    pub fn to_log_entry(&self) -> serde_json::Value {
        serde_json::json!({
            "error_type": std::any::type_name::<Self>(),
            "severity": self.severity(),
            "category": self.category(),
            "retryable": self.is_retryable(),
            "message": self.to_string(),
            "recovery_suggestions": self.recovery_suggestions(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "details": self.clone()
        })
    }
}

/// Result type alias for zkEVM operations
pub type ZkEvmResult<T> = Result<T, ZkEvmError>;

/// Error context for chaining errors with additional information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub operation: String,
    pub component: String,
    pub block_number: Option<u64>,
    pub transaction_hash: Option<String>,
    pub additional_data: std::collections::HashMap<String, String>,
}

impl ErrorContext {
    pub fn new(operation: &str, component: &str) -> Self {
        Self {
            operation: operation.to_string(),
            component: component.to_string(),
            block_number: None,
            transaction_hash: None,
            additional_data: std::collections::HashMap::new(),
        }
    }

    pub fn with_block(mut self, block_number: u64) -> Self {
        self.block_number = Some(block_number);
        self
    }

    pub fn with_transaction(mut self, tx_hash: &str) -> Self {
        self.transaction_hash = Some(tx_hash.to_string());
        self
    }

    pub fn with_data(mut self, key: &str, value: &str) -> Self {
        self.additional_data.insert(key.to_string(), value.to_string());
        self
    }
}

/// Trait for enriching errors with context
pub trait ErrorContextExt<T> {
    fn with_context(self, context: ErrorContext) -> ZkEvmResult<T>;
    fn with_operation(self, operation: &str, component: &str) -> ZkEvmResult<T>;
}

impl<T, E> ErrorContextExt<T> for Result<T, E>
where
    E: Into<ZkEvmError>,
{
    fn with_context(self, context: ErrorContext) -> ZkEvmResult<T> {
        self.map_err(|e| {
            let mut error = e.into();
            // Enhance error with context information
            match &mut error {
                ZkEvmError::InternalError { context: ref mut ctx, .. } => {
                    *ctx = format!("{} | {}", ctx, serde_json::to_string(&context).unwrap_or_default());
                },
                _ => {
                    // For other error types, we could enhance them with context as well
                }
            }
            error
        })
    }

    fn with_operation(self, operation: &str, component: &str) -> ZkEvmResult<T> {
        self.with_context(ErrorContext::new(operation, component))
    }
}

/// Macro for creating internal errors with file/line information
#[macro_export]
macro_rules! internal_error {
    ($msg:expr) => {{
        ZkEvmError::InternalError {
            message: $msg.to_string(),
            context: format!("{}:{}", file!(), line!()),
            stack_trace: Some(std::backtrace::Backtrace::capture().to_string()),
        }
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        ZkEvmError::InternalError {
            message: format!($fmt, $($arg)*),
            context: format!("{}:{}", file!(), line!()),
            stack_trace: Some(std::backtrace::Backtrace::capture().to_string()),
        }
    }};
}

/// Macro for creating performance degradation errors
#[macro_export]
macro_rules! performance_error {
    ($metric:expr, $value:expr, $threshold:expr, $duration:expr) => {{
        ZkEvmError::PerformanceDegradation {
            metric: $metric.to_string(),
            value: $value,
            threshold: $threshold,
            duration_ms: $duration,
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity_classification() {
        let proof_error = ZkEvmError::ProofGenerationFailed {
            message: "Test error".to_string(),
            details: "Test details".to_string(),
            proof_type: "ZODA".to_string(),
            block_number: Some(12345),
        };
        assert_eq!(proof_error.severity(), ErrorSeverity::Critical);
        assert_eq!(proof_error.category(), ErrorCategory::Cryptographic);
        assert!(!proof_error.is_retryable());
    }

    #[test]
    fn test_network_error_retry_logic() {
        let network_error = ZkEvmError::NetworkError {
            message: "Connection timeout".to_string(),
            endpoint: "https://mainnet.infura.io".to_string(),
            retry_count: 2,
        };
        assert!(network_error.is_retryable());
        assert_eq!(network_error.severity(), ErrorSeverity::Medium);

        let network_error_high_retries = ZkEvmError::NetworkError {
            message: "Connection timeout".to_string(),
            endpoint: "https://mainnet.infura.io".to_string(),
            retry_count: 5,
        };
        assert!(!network_error_high_retries.is_retryable());
        assert_eq!(network_error_high_retries.severity(), ErrorSeverity::High);
    }

    #[test]
    fn test_error_recovery_suggestions() {
        let config_error = ZkEvmError::ConfigurationError {
            message: "Invalid configuration".to_string(),
            config_path: "/etc/zkvm.toml".to_string(),
            invalid_fields: vec!["timeout".to_string(), "max_memory".to_string()],
        };
        let suggestions = config_error.recovery_suggestions();
        assert!(suggestions.len() >= 2);
        assert!(suggestions.iter().any(|s| s.contains("timeout, max_memory")));
    }

    #[test]
    fn test_error_context_enrichment() {
        let context = ErrorContext::new("proof_generation", "zoda_prover")
            .with_block(12345)
            .with_transaction("0xabc123")
            .with_data("proof_type", "ZODA-WARP");

        assert_eq!(context.operation, "proof_generation");
        assert_eq!(context.component, "zoda_prover");
        assert_eq!(context.block_number, Some(12345));
        assert_eq!(context.transaction_hash, Some("0xabc123".to_string()));
        assert_eq!(context.additional_data.get("proof_type"), Some(&"ZODA-WARP".to_string()));
    }
}
