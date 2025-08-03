// Core type definitions for the bundle relayer system

use std::collections::{HashMap, HashSet};
use std::fmt;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::str::FromStr;
use thiserror::Error;

/// Optimized witness data for StatelessVM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedWitnesses {
    /// The actual witness data
    pub data: Vec<String>,
    /// Total size of the witnesses in bytes
    pub total_size: u64,
}

impl OptimizedWitnesses {
    /// Create a new empty witness set
    pub fn empty() -> Self {
        Self {
            data: Vec::new(),
            total_size: 0,
        }
    }
    
    /// Get the number of witnesses
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the witness set is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Unique identifier for transaction bundles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BundleId(pub Uuid);

impl BundleId {
    /// Create a new random bundle ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    
    /// Convert to string representation
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for BundleId {
    type Err = uuid::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transaction hash type
pub type TxHash = String;

/// Ethereum address type
pub type Address = String;

/// Blockchain agnostic transaction representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// Transaction hash
    pub hash: TxHash,
    /// Raw signed transaction data
    pub data: Vec<u8>,
    /// Transaction sender address (derived from signature)
    pub from: Address,
    /// Transaction recipient address (if applicable)
    pub to: Option<Address>,
    /// Transaction value in wei
    pub value: String,
    /// Gas price in wei
    pub gas_price: String,
    /// Gas limit
    pub gas_limit: String,
    /// Transaction nonce
    pub nonce: u64,
    /// Chain ID
    pub chain_id: u64,
}

/// Bundle of transactions to be executed atomically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBundle {
    /// Bundle identifier
    pub bundle_id: BundleId,
    /// List of signed transactions
    pub transactions: Vec<SignedTransaction>,
    /// Submitter address (optional, for attribution)
    pub submitter: Option<Address>,
    /// Timestamp when bundle was created
    pub created_at: DateTime<Utc>,
    /// Optional metadata about the bundle
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Transaction validity window (in blocks)
    pub validity_window: BlockValidityWindow,
}

/// Window of validity for bundle execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockValidityWindow {
    /// Starting block number (inclusive)
    pub start_block: Option<u64>,
    /// Ending block number (inclusive)
    pub end_block: Option<u64>,
}

/// Status code for bundle execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BundleStatusCode {
    /// Unknown status
    Unknown,
    /// Bundle was received and stored
    Received,
    /// Bundle is being validated
    Validating,
    /// Bundle validation failed
    ValidationFailed,
    /// Bundle was validated and is awaiting simulation
    Validated,
    /// Bundle is generating optimized witnesses with StatelessVM
    GeneratingWitnesses,
    /// Bundle witness generation failed
    WitnessGenerationFailed,
    /// Bundle is being simulated
    Simulating,
    /// Bundle simulation failed
    SimulationFailed,
    /// Bundle was simulated successfully and is awaiting submission
    Simulated,
    /// Bundle is being submitted to blockchain
    Submitting,
    /// Bundle submission failed
    SubmissionFailed,
    /// Bundle was submitted and is awaiting confirmation
    Submitted,
    /// Bundle was mined and confirmed
    Confirmed,
    /// Bundle was rejected by blockchain
    Rejected,
    /// Bundle execution timed out
    Timeout,
    /// Bundle was dropped (e.g. due to low value)
    Dropped,
}

impl fmt::Display for BundleStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleStatusCode::Unknown => write!(f, "unknown"),
            BundleStatusCode::Received => write!(f, "received"),
            BundleStatusCode::Validating => write!(f, "validating"),
            BundleStatusCode::ValidationFailed => write!(f, "validation_failed"),
            BundleStatusCode::Validated => write!(f, "validated"),
            BundleStatusCode::GeneratingWitnesses => write!(f, "generating_witnesses"),
            BundleStatusCode::WitnessGenerationFailed => write!(f, "witness_generation_failed"),
            BundleStatusCode::Simulating => write!(f, "simulating"),
            BundleStatusCode::SimulationFailed => write!(f, "simulation_failed"),
            BundleStatusCode::Simulated => write!(f, "simulated"),
            BundleStatusCode::Submitting => write!(f, "submitting"),
            BundleStatusCode::SubmissionFailed => write!(f, "submission_failed"),
            BundleStatusCode::Submitted => write!(f, "submitted"),
            BundleStatusCode::Confirmed => write!(f, "confirmed"),
            BundleStatusCode::Rejected => write!(f, "rejected"),
            BundleStatusCode::Timeout => write!(f, "timeout"),
            BundleStatusCode::Dropped => write!(f, "dropped"),
        }
    }
}

/// Status code for transaction execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionStatusCode {
    /// Transaction is pending
    Pending,
    /// Transaction was mined in a block
    Mined,
    /// Transaction was confirmed (enough confirmations)
    Confirmed,
    /// Transaction failed during execution
    Failed,
    /// Transaction was dropped from mempool
    Dropped,
}

impl fmt::Display for TransactionStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionStatusCode::Pending => write!(f, "pending"),
            TransactionStatusCode::Mined => write!(f, "mined"),
            TransactionStatusCode::Confirmed => write!(f, "confirmed"),
            TransactionStatusCode::Failed => write!(f, "failed"),
            TransactionStatusCode::Dropped => write!(f, "dropped"),
        }
    }
}

/// Bundle status with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStatus {
    /// Bundle identifier
    pub bundle_id: BundleId,
    /// Status code
    pub status_code: BundleStatusCode,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Transaction hashes in the bundle
    pub transaction_hashes: Vec<TxHash>,
    /// Block number (if mined)
    pub block_number: Option<u64>,
    /// Gas used (if mined)
    pub gas_used: Option<String>,
    /// Error message (if any)
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Performance metrics
    pub performance: Option<PerformanceMetrics>,
}

/// Performance metrics for bundle processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Timestamp when submission process started (Unix timestamp in ms)
    pub submission_started_at: Option<u64>,
    /// Time spent validating the bundle (ms)
    pub validation_time_ms: Option<u64>,
    /// Time spent simulating the bundle (ms)
    pub simulation_time_ms: Option<u64>,
    /// Time spent submitting the bundle (ms)
    pub submission_time_ms: Option<u64>,
    /// Time spent waiting for confirmation (ms)
    pub confirmation_time_ms: Option<u64>,
    /// Total time from receipt to completion (ms)
    pub total_time_ms: Option<u64>,
    /// Gas efficiency score (0-100)
    pub gas_efficiency_score: Option<u8>,
    /// Number of resubmission attempts
    pub retry_count: Option<u32>,
    /// Number of submission attempts (including retries)
    pub submission_attempts: Option<u32>,
    /// Time spent optimizing witnesses (ms)
    pub witness_optimization_ms: Option<u64>,
    /// Time spent encoding witnesses (ms)
    pub witness_encoding_ms: Option<u64>,
    /// Size of the optimized witnesses in bytes
    pub witness_size_bytes: Option<u64>,
    /// Time spent encoding transaction data (ms)
    pub tx_encoding_ms: Option<u64>,
    /// Time spent estimating gas (ms)
    pub gas_estimation_ms: Option<u64>,
    /// Transaction hash if submitted successfully
    pub tx_hash: Option<String>,
    /// Block number where transaction was included
    pub block_number: Option<u64>,
    /// Gas used by the transaction
    pub gas_used: Option<u64>,
    /// Whether the transaction was executed successfully
    pub tx_success: Option<bool>,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            submission_started_at: None,
            validation_time_ms: None,
            simulation_time_ms: None,
            submission_time_ms: None,
            confirmation_time_ms: None,
            total_time_ms: None,
            gas_efficiency_score: None,
            retry_count: None,
            submission_attempts: None,
            witness_optimization_ms: None,
            witness_encoding_ms: None,
            witness_size_bytes: None,
            tx_encoding_ms: None,
            gas_estimation_ms: None,
            tx_hash: None,
            block_number: None,
            gas_used: None,
            tx_success: None,
        }
    }
}

/// Detailed simulation result from the StatelessVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Bundle identifier
    pub bundle_id: BundleId,
    /// Whether the simulation was successful
    pub success: bool,
    /// Gas used during simulation
    pub gas_used: u64,
    /// Detailed execution trace (if available)
    pub execution_trace: Option<Vec<TraceItem>>,
    /// Time taken for simulation in milliseconds
    pub duration_ms: u64,
    /// Error message if simulation failed
    pub error: Option<String>,
}

/// Individual trace item from StatelessVM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceItem {
    /// Transaction hash
    pub tx_hash: String,
    /// Execution step number
    pub step: u32,
    /// Operation being executed
    pub operation: String,
    /// Gas used by this operation
    pub gas_used: u64,
    /// Status of the operation
    pub status: String,
}

/// Transaction status with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatus {
    /// Transaction hash
    pub hash: TxHash,
    /// Status code
    pub status_code: TransactionStatusCode,
    /// Block number (if mined)
    pub block_number: Option<u64>,
    /// Gas used (if mined)
    pub gas_used: Option<String>,
    /// Error message (if any)
    pub error: Option<String>,
    /// Transaction index in the block
    pub transaction_index: Option<u64>,
}

/// Bundle submission receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSubmissionReceipt {
    /// Bundle identifier
    pub bundle_id: BundleId,
    /// Timestamp when bundle was submitted
    pub submitted_at: DateTime<Utc>,
    /// Estimated block number when bundle will be mined
    pub estimated_block: Option<u64>,
    /// Any additional data for tracking the bundle
    pub receipt_data: Option<String>,
}

/// Agent metadata for bundle attribution and tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    /// Unique agent identifier
    pub agent_id: String,
    /// Agent version
    pub version: String,
    /// Type of agent
    pub agent_type: String, 
    /// Environment (production, staging, development)
    pub environment: String,
    /// Custom metadata
    pub custom: Option<HashMap<String, serde_json::Value>>,
}

/// Market state data for transaction sequence execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketState {
    /// Asset prices keyed by token address
    pub prices: HashMap<String, f64>,
    /// Market liquidity information keyed by pool address
    pub liquidity: HashMap<String, u64>,
    /// Gas price data
    pub gas_price: u64,
    /// Market volatility indicators
    pub volatility: HashMap<String, f64>,
    /// Timestamp when this market state was captured
    pub timestamp: u64,
}

/// MEV protection settings for transaction sequence execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtection {
    /// Whether to use private mempool for transactions
    pub use_private_mempool: bool,
    /// Frontrunning protection level (0-100)
    pub frontrunning_protection: u8,
    /// Maximum allowed slippage percentage
    pub max_slippage_percent: f64,
    /// Whether to monitor for sandwich attacks
    pub monitor_sandwich_attacks: bool,
    /// Commitment pattern for sensitive operations
    pub use_commit_reveal: bool,
}

/// State verification requirements for transaction sequence steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerification {
    /// Contract addresses to verify state for
    pub contracts: Vec<String>,
    /// Storage slots to verify for each contract
    pub storage_slots: HashMap<String, Vec<String>>,
    /// Balance requirements to verify
    pub balance_requirements: HashMap<String, String>,
    /// Custom verification expressions (contract-specific)
    pub custom_requirements: Option<serde_json::Value>,
}

/// Fallback plan for transaction sequence execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPlan {
    /// Transactions to execute on failure
    pub transactions: Vec<SignedTransaction>,
    /// Conditions under which to trigger this fallback
    pub trigger_conditions: serde_json::Value,
    /// Priority of this fallback plan (lower executes first)
    pub priority: u8,
    /// Description of the fallback plan
    pub description: String,
}

/// Transaction sequence for coordinated execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSequence {
    /// Unique identifier for the sequence
    pub sequence_id: String,
    /// The main transactions to execute in order
    pub transactions: Vec<SignedTransaction>,
    /// Optional fallback plans if main transactions fail
    pub fallback_plans: Option<Vec<FallbackPlan>>,
    /// Market conditions that must be met for execution
    pub market_conditions: Option<serde_json::Value>,
    /// MEV protection settings
    pub mev_protection: Option<MevProtection>,
    /// State verification requirements between steps
    pub state_verification: Option<Vec<StateVerification>>,
    /// Timeout for the entire sequence in seconds
    pub timeout_seconds: u64,
    /// Whether steps must be executed atomically
    pub atomic: bool,
    /// Custom execution metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Configuration for bundle security validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Level of validation to perform
    pub validation_level: SecurityValidationLevel,
    /// Maximum gas allowed per bundle
    pub max_bundle_gas: u64,
    /// Maximum number of transactions in a bundle
    pub max_bundle_size: u32,
    /// Security verification mode ("always", "deployment_only", "high_value_only", "disabled")
    pub verification_mode: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            validation_level: SecurityValidationLevel::Standard,
            max_bundle_gas: 15_000_000,
            max_bundle_size: 100,
            verification_mode: "always".to_string(),
        }
    }
}

/// Security validation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityValidationLevel {
    /// No validation
    None,
    /// Basic validation only (signatures, formats)
    Basic,
    /// Standard security checks
    Standard,
    /// Comprehensive security analysis
    Comprehensive,
}

/// Security warning severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Low severity issue
    Low,
    /// Medium severity issue 
    Medium,
    /// High severity issue
    High,
    /// Critical severity issue
    Critical,
}

/// Security warning for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    /// Type of warning
    pub kind: String,
    /// Warning severity
    pub severity: Severity,
    /// Warning description
    pub description: String,
    /// Bytecode offset (if applicable)
    pub offset: Option<usize>,
    /// Recommended remediation
    pub remediation: Option<String>,
}

/// Security proof for a bundle or transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProof {
    /// Encoded proof data
    pub proof_data: Option<String>,
    /// Security warnings identified
    pub warnings: Vec<SecurityWarning>,
    /// When the proof was generated
    pub generated_at: DateTime<Utc>,
    /// Validator subnet ID
    pub validator_subnet_id: Option<String>,
}

/// Error types for the application
#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("Invalid bundle: {0}")]
    InvalidBundle(String),
    
    #[error("Transaction error: {0}")]
    TransactionError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("API error: {0}")]
    ApiError(String),
    
    #[error("Security error: {0}")]
    SecurityError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}
