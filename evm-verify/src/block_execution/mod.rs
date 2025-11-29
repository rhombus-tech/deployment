// ZODA Block Execution Engine
//
// High-performance block execution with tensor-optimized proving
// Designed to maintain 3-7s proving times for full Ethereum blocks
// on CPU-only hardware while providing mathematical execution guarantees

pub mod block_executor;
pub mod batch_processor;
pub mod state_accumulator;
pub mod transaction_processor;
pub mod block_validator;
pub mod performance_monitor;

#[cfg(test)]
mod tests;

pub use block_executor::{BlockExecutor, BlockExecutionResult};
pub use batch_processor::{BatchProcessor, BatchResult, TransactionBatch};
pub use state_accumulator::{StateAccumulator, StateTransition, AccumulationResult};
pub use transaction_processor::{TransactionProcessor, TransactionResult, ProcessingMode, ProcessingBatch};
pub use block_validator::{BlockValidator, ValidationResult, ValidationConfig};
pub use performance_monitor::{PerformanceMonitor, PerformanceReport, ExecutionMetrics};

// Re-export key types for convenience
pub use crate::api::pcd::PCDVerifier;
pub use crate::api::pcd_adapter::PCDAdapter;

// 🚀 WARP/FRI: No longer using EVMAccumulator (Groth16)
// Block-level WARP/FRI proofs handle all verification

use ethers::types::{Block, Transaction, U256};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Core block execution engine that orchestrates the entire process
pub struct ZODABlockEngine {
    pub executor: Arc<BlockExecutor>,
    pub batch_processor: Arc<BatchProcessor>,
    pub state_accumulator: Arc<Mutex<StateAccumulator>>,
    pub validator: Arc<BlockValidator>,
    pub performance_monitor: Arc<Mutex<PerformanceMonitor>>,
    pub config: BlockExecutionConfig,
}

impl ZODABlockEngine {
    /// Create a new ZODA block execution engine
    pub fn new(config: BlockExecutionConfig) -> Result<Self> {
        let executor = Arc::new(BlockExecutor::new(config.clone())?);
        let batch_processor = Arc::new(BatchProcessor::new(config.clone())?);
        let state_accumulator = Arc::new(Mutex::new(StateAccumulator::new()?));
        let validator = Arc::new(BlockValidator::new(config.clone())?);
        let performance_monitor = Arc::new(Mutex::new(PerformanceMonitor::new(config.clone())?));

        Ok(Self {
            executor,
            batch_processor,
            state_accumulator,
            validator,
            performance_monitor,
            config,
        })
    }

    /// Execute a complete block with ZODA tensor optimization
    pub async fn execute_block(&self, block: Block<Transaction>) -> Result<BlockExecutionResult> {
        let start_time = std::time::Instant::now();
        
        // Start performance monitoring - record will be done at completion

        // Phase 1: Validate block structure and constraints
        let validation_result = self.validator.validate_block(&block).await?;
        if !validation_result.is_valid {
            return Err(anyhow!("Block validation failed: {:?}", validation_result.errors));
        }

        // Phase 2: Process transactions in optimized batches
        let batch_result = self.batch_processor.process_block_transactions(&block).await?;

        // Phase 3: Accumulate state transitions with tensor compression
        let mut accumulator = self.state_accumulator.lock().await;
        let accumulation_result = accumulator.accumulate_block_state(&batch_result).await?;
        drop(accumulator);

        // Phase 4: Generate final block proof
        let execution_result = self.executor.finalize_block_execution(
            &block,
            &batch_result,
            &accumulation_result,
        ).await?;

        // Record performance metrics
        let execution_time = start_time.elapsed();
        let monitor = self.performance_monitor.lock().await;
        monitor.record_block_execution(execution_time, true).await?;

        Ok(execution_result)
    }

    /// Get current performance metrics
    pub async fn get_performance_metrics(&self) -> PerformanceReport {
        let monitor = self.performance_monitor.lock().await;
        monitor.generate_report().await.unwrap_or_default()
    }

    /// Health check for the block execution engine
    pub async fn health_check(&self) -> Result<bool> {
        // Verify all components are operational
        let validator_ok = self.validator.health_check().await?;
        let processor_ok = self.batch_processor.health_check().await?;
        let executor_ok = self.executor.health_check().await?;

        Ok(validator_ok && processor_ok && executor_ok)
    }
}

/// Configuration for block execution engine
#[derive(Debug, Clone)]
pub struct BlockExecutionConfig {
    /// Maximum transactions to process in parallel
    pub max_parallel_transactions: usize,
    
    /// Enable tensor batch optimization
    pub enable_tensor_optimization: bool,
    
    /// Target proving time in seconds
    pub target_proving_time_seconds: u64,
    
    /// CPU threads to use for proof generation
    pub cpu_threads: usize,
    
    /// Enable performance monitoring
    pub enable_performance_monitoring: bool,
    
    /// Gas limit for block execution
    pub gas_limit: U256,
    
    /// Chain ID for block execution
    pub chain_id: u64,
    
    /// Enable vulnerability analysis (optional security layer)
    pub enable_vulnerability_analysis: bool,
    
    /// Apply vulnerability analysis selectively (only new contracts)
    pub selective_vulnerability_analysis: bool,
}

impl Default for BlockExecutionConfig {
    fn default() -> Self {
        Self {
            max_parallel_transactions: 16, // Optimal for CPU parallelization
            enable_tensor_optimization: true,
            target_proving_time_seconds: 7, // Under Ethereum's 10s requirement
            cpu_threads: num_cpus::get(),
            enable_performance_monitoring: true,
            gas_limit: U256::from(60_000_000), // Updated for current Ethereum mainnet gas limits
            chain_id: 1, // Ethereum mainnet
            enable_vulnerability_analysis: false, // Disabled by default for EF zkEVM compliance
            selective_vulnerability_analysis: true, // When enabled, only analyze new contracts
        }
    }
}
// Tests are in tests.rs file
