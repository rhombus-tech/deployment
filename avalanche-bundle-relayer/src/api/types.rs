// API type definitions

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

use crate::types::{
    BundleId, TxHash, BundleStatusCode, TransactionStatusCode, AgentMetadata,
    SecurityWarning, BundleStatus, BlockValidityWindow, SignedTransaction
};

/// API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success status
    pub success: bool,
    /// Response data (if success is true)
    pub data: Option<T>,
    /// Error message (if success is false)
    pub error: Option<String>,
    /// Request ID for tracking
    pub request_id: String,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T, request_id: Option<String>) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            request_id: request_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            timestamp: Utc::now(),
        }
    }
    
    /// Create an error response
    pub fn error(error: impl Into<String>, request_id: Option<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.into()),
            request_id: request_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            timestamp: Utc::now(),
        }
    }
}

/// Bundle submission request
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleSubmissionRequest {
    /// List of signed transactions
    pub transactions: Vec<SignedTransaction>,
    /// Agent metadata
    pub agent: Option<AgentMetadata>,
    /// Transaction validity window in blocks
    pub validity_window: Option<BlockValidityWindow>,
}

/// Bundle status response
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleStatusResponse {
    /// Bundle ID
    pub bundle_id: BundleId,
    /// Status code
    pub status: BundleStatusCode,
    /// Transactions in the bundle
    pub transactions: Vec<TxHash>,
    /// Block number (if confirmed)
    pub block_number: Option<u64>,
    /// Timestamp when the bundle was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the status was last updated
    pub updated_at: DateTime<Utc>,
    /// Error message (if any)
    pub error: Option<String>,
    /// Performance metrics
    pub performance: Option<PerformanceMetricsResponse>,
    /// Security warnings (if any)
    pub warnings: Option<Vec<SecurityWarning>>,
}

/// Enhanced bundle status with more details
#[derive(Debug, Serialize, Deserialize)]
pub struct EnhancedBundleStatus {
    /// Bundle ID
    pub bundle_id: BundleId,
    /// Current processing phase
    pub phase: String,
    /// Agent ID that submitted the bundle
    pub agent_id: Option<String>,
    /// Bundle priority
    pub priority: u8,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Bundle metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Performance metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetricsResponse {
    /// Time spent in validation (ms)
    pub validation_time_ms: Option<u64>,
    /// Time spent in simulation (ms)
    pub simulation_time_ms: Option<u64>,
    /// Time spent in submission (ms)
    pub submission_time_ms: Option<u64>,
    /// Time spent waiting for confirmation (ms)
    pub confirmation_time_ms: Option<u64>,
    /// Total processing time (ms)
    pub total_time_ms: Option<u64>,
    /// Gas efficiency score (0-100)
    pub gas_efficiency_score: Option<u8>,
    /// Number of retry attempts
    pub retry_count: Option<u32>,
}

/// Convert from BundleStatus to BundleStatusResponse
impl From<BundleStatus> for BundleStatusResponse {
    fn from(status: BundleStatus) -> Self {
        let performance = status.performance.map(|p| PerformanceMetricsResponse {
            validation_time_ms: p.validation_time_ms,
            simulation_time_ms: p.simulation_time_ms,
            submission_time_ms: p.submission_time_ms,
            confirmation_time_ms: p.confirmation_time_ms,
            total_time_ms: p.total_time_ms,
            gas_efficiency_score: p.gas_efficiency_score,
            retry_count: p.retry_count,
        });
        
        Self {
            bundle_id: status.bundle_id,
            status: status.status_code,
            transactions: status.transaction_hashes,
            block_number: status.block_number,
            created_at: status.created_at,
            updated_at: status.updated_at,
            error: status.error,
            performance,
            warnings: None, // Security warnings would be added separately
        }
    }
}

/// Websocket event types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[derive(Clone)]
pub enum WebSocketEvent {
    /// Bundle status update event
    #[serde(rename = "bundle_status")]
    BundleStatus {
        bundle_id: BundleId,
        status: BundleStatusCode,
        timestamp: DateTime<Utc>,
        details: Option<serde_json::Value>,
    },
    
    /// Transaction status update event
    #[serde(rename = "transaction_status")]
    TransactionStatus {
        hash: TxHash,
        bundle_id: Option<BundleId>,
        status: TransactionStatusCode,
        block_number: Option<u64>,
        timestamp: DateTime<Utc>,
    },
    
    /// Error event
    #[serde(rename = "error")]
    Error {
        code: String,
        message: String,
        timestamp: DateTime<Utc>,
    },
    
    /// Heartbeat event
    #[serde(rename = "heartbeat")]
    Heartbeat {
        timestamp: DateTime<Utc>,
    },
}
