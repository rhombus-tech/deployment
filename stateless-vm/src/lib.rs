pub mod api;
pub mod core;
pub mod errors;
pub mod pcd;
pub mod prelude;
pub mod realtime;
pub mod state;
pub mod transaction;
pub mod types;
pub mod security;
pub mod atomic;
pub mod parallel;
pub mod pcd;
pub mod agents;
pub mod utils;
pub mod api;

pub use crate::core::{StatelessVM, ExecutionMode, ExecutionResult};
pub use crate::errors::VMError;
pub use crate::transaction::{Transaction, TransactionSequence, TransactionStatus, FallbackPlan, MarketConditions, MevProtectionSettings, StateVerificationConfig};
pub use crate::state::StateBundler;
pub use crate::pcd::PCDVerifierFactory;
pub use crate::atomic::{AtomicExecutor, AtomicExecutionResult, VerifiedAtomicResult, ExecutionProof, AtomicOperation};
pub use crate::parallel::{ParallelExecutionEngine, ParallelExecutionMetrics, ParallelizationEfficiency};

/// Convenience re-exports of essential types
pub mod prelude {
    pub use crate::core::{StatelessVM, ExecutionMode, ExecutionResult};
    pub use crate::errors::{VMError, Result};
    pub use crate::transaction::{Transaction, TransactionSequence, TransactionStatus};
    pub use crate::state::{StateBundler, StateProvider, StateRequirement, StateAccessPattern};
    pub use crate::agents::{AgentAction, AgentInterface};
    pub use crate::security::{SecurityVerifier, VerificationResult};
    pub use crate::pcd::PCDVerifierFactory;
    pub use crate::types::{Address, Bytes, BlockHeight, Gas, StorageKey, StorageValue};
    pub use crate::atomic::{AtomicExecutor, AtomicExecutionResult, VerifiedAtomicResult};
}
