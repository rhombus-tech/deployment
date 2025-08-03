use thiserror::Error;
use crate::types::{Address, TransactionId, StateRoot, BlockHeight};
use std::fmt;

/// Specialized Result type for the VM
pub type Result<T> = std::result::Result<T, VMError>;

/// Errors that can occur during VM execution
#[derive(Error, Debug)]
pub enum VMError {
    /// Insufficient gas to complete the operation
    #[error("Insufficient gas: required {required}, available {available}")]
    InsufficientGas {
        required: u64,
        available: u64,
    },

    /// Missing state that was required but not provided
    #[error("Missing state for {address} at key {key}: {description}")]
    MissingState {
        address: Address,
        key: String,
        description: String,
    },

    /// Invalid operation attempted
    #[error("Invalid operation: {description}")]
    InvalidOperation {
        description: String,
    },

    /// Execution reverted by contract
    #[error("Execution reverted: {reason}")]
    ExecutionReverted {
        reason: String,
    },

    /// Security verification failed
    #[error("Security verification failed: {reason}")]
    SecurityVerificationFailed {
        reason: String,
    },

    /// Invalid transaction format
    #[error("Invalid transaction format: {reason}")]
    InvalidTransaction {
        reason: String,
    },

    /// State inconsistency detected
    #[error("State inconsistency detected: expected root {expected_root}, computed {computed_root}")]
    StateInconsistency {
        expected_root: StateRoot,
        computed_root: StateRoot,
    },

    /// Sequence execution error
    #[error("Error executing sequence at step {step}: {reason}")]
    SequenceError {
        step: usize,
        reason: String,
    },

    /// Agent execution error
    #[error("Error executing agent actions: {description}")]
    AgentError {
        description: String,
    },
    
    /// Market condition violation
    #[error("Market condition violated at transaction {tx_index}: {description}")]
    MarketConditionViolation {
        description: String,
        tx_index: usize,
    },
    
    /// MEV protection failure
    #[error("MEV protection failed: {reason}")]
    MevProtectionFailed {
        reason: String,
    },
    
    /// State verification failure
    #[error("State verification failed between steps {tx_index} and {next_tx_index}: {description}")]
    StateVerificationFailed {
        tx_index: usize,
        next_tx_index: usize,
        description: String,
    },
    
    /// Nonce management error
    #[error("Nonce management error for address {address}: {description}")]
    NonceError {
        address: Address,
        description: String,
    },
    
    /// Atomic transaction failure
    #[error("Atomic transaction sequence failed: {reason}")]
    AtomicSequenceFailed {
        reason: String,
    },
    
    /// Transaction revert failure
    #[error("Failed to revert transaction {tx_id}: {reason}")]
    RevertFailed {
        tx_id: TransactionId,
        reason: String,
    },

    /// Dependency cycle detected
    #[error("Dependency cycle detected in transaction sequence")]
    DependencyCycle,

    /// Stale state: state is from an older block than required
    #[error("Stale state: provided from block {provided_block}, required {required_block}")]
    StaleState {
        provided_block: BlockHeight,
        required_block: BlockHeight,
    },

    /// Transaction dependency not found
    #[error("Transaction dependency not found: {transaction_id}")]
    DependencyNotFound {
        transaction_id: TransactionId,
    },

    /// State root validation failed
    #[error("State root validation failed")]
    StateRootValidationFailed,

    /// Internal error
    #[error("Internal error: {description}")]
    Internal {
        description: String,
    },

    /// Proof generation failed
    #[error("Proof generation failed: {reason}")]
    ProofGenerationFailed {
        reason: String,
    },

    /// Proof verification failed
    #[error("Proof verification failed: {reason}")]
    ProofVerificationFailed {
        reason: String,
    },

    /// I/O error
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Error from anyhow
    #[error("External error: {0}")]
    External(String),
}

// Implement From<anyhow::Error> for VMError
impl From<anyhow::Error> for VMError {
    fn from(err: anyhow::Error) -> Self {
        VMError::External(err.to_string())
    }
}
