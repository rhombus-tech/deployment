// Error definitions for the bundle relayer

use thiserror::Error;
use warp::reject::Reject;
use std::fmt;

/// Custom errors for the relayer system
#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("Bundle not found: {0}")]
    BundleNotFound(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Simulation failed: {0}")]
    SimulationFailed(String),
    
    #[error("Submission failed: {0}")]
    SubmissionFailed(String),
    
    #[error("Witness generation failed: {0}")]
    WitnessGenerationFailed(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Security error: {0}")]
    SecurityError(String),
    
    #[error("API error: {0}")]
    ApiError(String),
    
    #[error("Authentication error: {0}")]
    AuthError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Initialization error: {0}")]
    InitializationError(String),
    
    // Multi-step transaction coordination errors
    #[error("Market condition violation: {0}")]
    MarketConditionViolation(String),
    
    #[error("MEV protection failure: {0}")]
    MevProtectionFailure(String),
    
    #[error("Transaction sequence error: {0}")]
    TransactionSequenceError(String),
    
    #[error("Fallback execution failed: {0}")]
    FallbackExecutionFailed(String),
    
    #[error("State verification failed: {0}")]
    StateVerificationFailed(String),
}

/// Warp-compatible API error for rejection
#[derive(Debug)]
pub struct ApiError(pub String);

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Reject for ApiError {}

/// Result type alias for RelayerError
pub type Result<T> = std::result::Result<T, RelayerError>;
