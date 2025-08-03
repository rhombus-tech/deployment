// ZODA Production Error Handling System
// 
// Comprehensive error types and recovery strategies for production deployment

use std::time::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Comprehensive ZODA error types for production systems
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ZodaError {
    // ===============================
    // CRYPTOGRAPHIC COMPUTATION ERRORS
    // ===============================
    
    /// Tensor computation matrix dimension mismatch
    #[error("Matrix dimension mismatch: expected {expected:?}, got {got:?}")]
    MatrixDimensionMismatch { 
        expected: (usize, usize), 
        got: (usize, usize) 
    },
    
    /// Reed-Solomon syndrome validation failed
    #[error("Syndrome validation failed: {row_failures} row failures, {col_failures} column failures")]
    SyndromeValidationFailed { 
        row_failures: Vec<usize>, 
        col_failures: Vec<usize> 
    },
    
    /// Reed-Solomon decoding completely failed
    #[error("Reed-Solomon decoding failed: {error_count} errors detected, max correctable: {max_correctable}")]
    ReedSolomonDecodingFailed { 
        error_count: usize, 
        max_correctable: usize 
    },
    
    /// Tensor compression ratio below acceptable threshold
    #[error("Tensor compression failed: ratio {actual_ratio:.2}x below minimum {min_ratio:.2}x")]
    TensorCompressionInsufficient { 
        actual_ratio: f64, 
        min_ratio: f64 
    },
    
    /// Multilinear polynomial evaluation failed
    #[error("Multilinear polynomial evaluation failed at point {evaluation_point:?}")]
    MultilinearEvaluationFailed { 
        evaluation_point: Vec<u8> 
    },

    // ===============================
    // EVM EXECUTION ERRORS
    // ===============================
    
    /// EVM execution exceeded timeout limit
    #[error("EVM execution timeout: exceeded {max_duration:?}")]
    EvmExecutionTimeout { 
        max_duration: Duration 
    },
    
    /// Invalid or malformed bytecode
    #[error("Invalid bytecode: {reason}")]
    InvalidBytecode { 
        reason: String 
    },
    
    /// Insufficient gas for transaction execution
    #[error("Insufficient gas: required {required}, available {available}")]
    InsufficientGas { 
        required: u64, 
        available: u64 
    },
    
    /// Stack overflow during EVM execution
    #[error("EVM stack overflow: depth {current_depth} exceeded maximum {max_depth}")]
    EvmStackOverflow { 
        current_depth: usize, 
        max_depth: usize 
    },
    
    /// Memory access out of bounds
    #[error("Memory access violation: tried to access {address}, memory size {memory_size}")]
    MemoryAccessViolation { 
        address: usize, 
        memory_size: usize 
    },

    // ===============================
    // NETWORK AND SERIALIZATION ERRORS
    // ===============================
    
    /// Proof serialization failed due to size constraints
    #[error("Proof serialization failed: size {size} bytes exceeds maximum {max_size} bytes")]
    ProofSerializationFailed { 
        size: usize, 
        max_size: usize 
    },
    
    /// Network request timeout
    #[error("Network timeout: endpoint {endpoint} failed after {duration:?}")]
    NetworkTimeout { 
        endpoint: String, 
        duration: Duration 
    },
    
    /// Invalid block data received from network
    #[error("Invalid block data: block {block_number} - {reason}")]
    InvalidBlockData { 
        block_number: u64, 
        reason: String 
    },
    
    /// RPC endpoint returned invalid response
    #[error("RPC error: {method} call failed - {error_message}")]
    RpcError { 
        method: String, 
        error_message: String 
    },

    // ===============================
    // SYSTEM RESOURCE ERRORS
    // ===============================
    
    /// System memory exhausted
    #[error("Memory exhausted: used {used_mb}MB, limit {limit_mb}MB")]
    MemoryExhausted { 
        used_mb: usize, 
        limit_mb: usize 
    },
    
    /// CPU resources exceeded time limit 
    #[error("CPU time limit exceeded: used {used_seconds}s, limit {limit_seconds}s")]
    CpuTimeExceeded { 
        used_seconds: u64, 
        limit_seconds: u64 
    },
    
    /// Disk space insufficient for operation
    #[error("Disk space insufficient: need {needed_mb}MB, available {available_mb}MB")]
    DiskSpaceInsufficient { 
        needed_mb: u64, 
        available_mb: u64 
    },

    // ===============================
    // CONFIGURATION AND ENVIRONMENT ERRORS  
    // ===============================
    
    /// Invalid configuration value
    #[error("Configuration error: {parameter} = {value} is invalid - {reason}")]
    ConfigurationError { 
        parameter: String, 
        value: String, 
        reason: String 
    },
    
    /// Required environment variable missing
    #[error("Environment variable missing: {variable_name} is required")]
    EnvironmentVariableMissing { 
        variable_name: String 
    },
    
    /// Feature not available in current build
    #[error("Feature unavailable: {feature_name} not compiled in this build")]
    FeatureUnavailable { 
        feature_name: String 
    },

    // ===============================
    // RECOVERY AND RETRY ERRORS
    // ===============================
    
    /// Maximum retry attempts exceeded
    #[error("Max retries exceeded: attempted {attempts} times, last error: {last_error}")]
    MaxRetriesExceeded { 
        attempts: usize, 
        last_error: String 
    },
    
    /// Graceful degradation activated
    #[error("Graceful degradation: {feature} disabled due to {reason}")]
    GracefulDegradation { 
        feature: String, 
        reason: String 
    },
    
    /// Circuit breaker activated
    #[error("Circuit breaker open: {service} failure rate {failure_rate:.2}% exceeds {threshold:.2}%")]
    CircuitBreakerOpen { 
        service: String, 
        failure_rate: f64, 
        threshold: f64 
    },
}

/// Recovery strategies for different error types
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    /// Retry with exponential backoff
    RetryWithBackoff { 
        max_attempts: usize, 
        initial_delay: Duration 
    },
    
    /// Adjust parameters and retry
    AdjustParametersAndRetry {
        parameter_adjustments: Vec<(String, String)>
    },
    
    /// Gracefully degrade functionality
    GracefulDegradation {
        fallback_mode: String
    },
    
    /// Fail fast - no recovery possible
    FailFast,
    
    /// Circuit breaker - temporarily disable service
    CircuitBreaker {
        timeout: Duration
    },
}

impl ZodaError {
    /// Get the appropriate recovery strategy for this error type
    pub fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            // Cryptographic errors - usually need parameter adjustment
            ZodaError::MatrixDimensionMismatch { .. } => {
                RecoveryStrategy::AdjustParametersAndRetry {
                    parameter_adjustments: vec![
                        ("tensor_rows".to_string(), "auto_adjust".to_string()),
                        ("tensor_cols".to_string(), "auto_adjust".to_string()),
                    ]
                }
            },
            
            ZodaError::SyndromeValidationFailed { .. } => {
                RecoveryStrategy::AdjustParametersAndRetry {
                    parameter_adjustments: vec![
                        ("sampling_rate".to_string(), "increase_2x".to_string()),
                        ("error_threshold".to_string(), "relax_10%".to_string()),
                    ]
                }
            },
            
            ZodaError::TensorCompressionInsufficient { .. } => {
                RecoveryStrategy::GracefulDegradation {
                    fallback_mode: "uncompressed_tensor_mode".to_string()
                }
            },
            
            // Network errors - retry with backoff
            ZodaError::NetworkTimeout { .. } | ZodaError::RpcError { .. } => {
                RecoveryStrategy::RetryWithBackoff {
                    max_attempts: 3,
                    initial_delay: Duration::from_millis(1000),
                }
            },
            
            // Resource exhaustion - circuit breaker
            ZodaError::MemoryExhausted { .. } | ZodaError::CpuTimeExceeded { .. } => {
                RecoveryStrategy::CircuitBreaker {
                    timeout: Duration::from_secs(60)
                }
            },
            
            // Configuration errors - fail fast
            ZodaError::ConfigurationError { .. } | ZodaError::EnvironmentVariableMissing { .. } => {
                RecoveryStrategy::FailFast
            },
            
            // EVM execution errors - retry with timeout adjustment
            ZodaError::EvmExecutionTimeout { .. } => {
                RecoveryStrategy::AdjustParametersAndRetry {
                    parameter_adjustments: vec![
                        ("execution_timeout".to_string(), "increase_2x".to_string()),
                    ]
                }
            },
            
            // Default to retry for other errors
            _ => RecoveryStrategy::RetryWithBackoff {
                max_attempts: 2,
                initial_delay: Duration::from_millis(500),
            }
        }
    }
    
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        !matches!(self.recovery_strategy(), RecoveryStrategy::FailFast)
    }
    
    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ZodaError::ConfigurationError { .. } | 
            ZodaError::EnvironmentVariableMissing { .. } => ErrorSeverity::Critical,
            
            ZodaError::MemoryExhausted { .. } | 
            ZodaError::CpuTimeExceeded { .. } => ErrorSeverity::High,
            
            ZodaError::NetworkTimeout { .. } | 
            ZodaError::RpcError { .. } => ErrorSeverity::Medium,
            
            ZodaError::SyndromeValidationFailed { .. } |
            ZodaError::TensorCompressionInsufficient { .. } => ErrorSeverity::Low,
            
            _ => ErrorSeverity::Medium,
        }
    }
}

/// Error severity levels for monitoring and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Critical,  // System cannot continue
    High,      // Major functionality impaired  
    Medium,    // Some functionality impaired
    Low,       // Minor issues, system functional
}

impl std::fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::Low => write!(f, "LOW"),
        }
    }
}

/// Result type alias for ZODA operations
pub type ZodaResult<T> = Result<T, ZodaError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_recovery_strategies() {
        let matrix_error = ZodaError::MatrixDimensionMismatch { 
            expected: (32, 16), 
            got: (16, 32) 
        };
        
        assert!(matrix_error.is_retryable());
        assert_eq!(matrix_error.severity(), ErrorSeverity::Medium);
        
        match matrix_error.recovery_strategy() {
            RecoveryStrategy::AdjustParametersAndRetry { .. } => (),
            _ => panic!("Expected parameter adjustment recovery"),
        }
    }
    
    #[test]
    fn test_error_severity_levels() {
        let config_error = ZodaError::ConfigurationError {
            parameter: "ethereum_rpc_url".to_string(),
            value: "invalid".to_string(),
            reason: "not a valid URL".to_string(),
        };
        
        assert_eq!(config_error.severity(), ErrorSeverity::Critical);
        assert!(!config_error.is_retryable());
    }
}
