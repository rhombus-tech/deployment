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
pub mod streaming;
pub mod websocket;
pub mod accumulator;
pub mod realtime;
pub mod defi_protection;
pub mod contract_proof_cache;

pub use crate::core::{StatelessVM, ExecutionMode, ExecutionResult};
pub use crate::errors::VMError;
pub use crate::transaction::{Transaction, TransactionSequence, TransactionStatus, FallbackPlan, MarketConditions, MevProtectionSettings, StateVerificationConfig};
pub use crate::state::StateBundler;
pub use crate::pcd::PCDVerifierFactory;
pub use crate::atomic::{AtomicExecutor, AtomicExecutionResult, VerifiedAtomicResult, ExecutionProof, AtomicOperation};
pub use crate::parallel::{ParallelExecutionEngine, ParallelExecutionMetrics, ParallelizationEfficiency};
pub use crate::streaming::{ContinuousProvingEngine, ContinuousProvingConfig, StreamingTransaction, StreamingEvent, ProofAccumulationStrategy, TransactionPriority, OptimizationLevel};
pub use crate::websocket::{WSStreamingServer, WSStreamingClient, StreamType};
pub use crate::accumulator::{ProofAccumulator, CompressionAlgorithm, ProofChainSummary};
pub use crate::realtime::{RealTimeVerificationEngine, ValidationConfig};

// Prelude module moved inline to avoid module file issues
