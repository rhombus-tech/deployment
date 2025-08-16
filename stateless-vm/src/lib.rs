pub mod api;
pub mod core;
pub mod errors;
pub mod pcd;
pub mod state;
pub mod transaction;
pub mod types;
pub mod security;
pub mod atomic;
pub mod parallel;
pub mod agents;
pub mod utils;

pub use crate::core::{StatelessVM, ExecutionMode, ExecutionResult};
pub use crate::errors::VMError;
pub use crate::transaction::{Transaction, TransactionSequence, TransactionStatus, FallbackPlan, MarketConditions, MevProtectionSettings, StateVerificationConfig};
pub use crate::state::StateBundler;
pub use crate::pcd::PCDVerifierFactory;
pub use crate::atomic::{AtomicExecutor, AtomicExecutionResult, VerifiedAtomicResult, ExecutionProof, AtomicOperation};
pub use crate::parallel::{ParallelExecutionEngine, ParallelExecutionMetrics, ParallelizationEfficiency};

// Prelude module moved inline to avoid module file issues
