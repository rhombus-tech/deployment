use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use parking_lot::RwLock as ParkingLotRwLock;
use anyhow::Result;
use crate::errors::VMError;
use crate::state::{StateBundler, StateRequirement};
use crate::transaction::{Transaction, TransactionSequence, TransactionStatus, ExecutionContext};
use crate::security::{SecurityVerifier, VerificationResult};
use crate::atomic::{AtomicExecutor, AtomicExecutionResult, VerifiedAtomicResult};
use crate::parallel::{ParallelExecutionEngine, ParallelExecutionResult};
use crate::types::{Address, BlockHeight, StateRoot, VerificationLevel};
use crate::agents::{AgentInterface, AgentHandler, AgentContext};

/// Execution mode for the StatelessVM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Coordinated execution (current implementation)
    Coordinated,
    /// Atomic execution via smart contract bundling
    Atomic,
    /// Verified atomic execution with PCC+PCD proofs
    VerifiedAtomic,
    /// Parallel execution with automatic dependency resolution
    Parallel,
}

/// Core implementation of the stateless virtual machine
pub struct StatelessVM {
    /// Current block height (atomic for thread-safety)
    block_height: Arc<AtomicU64>,
    /// State bundler for packaging state with transactions
    state_bundler: Arc<RwLock<StateBundler>>,
    /// Security verification engine
    security_verifier: Arc<dyn SecurityVerifier>,
    /// Current state root (protected by parking_lot RwLock for better perf)
    state_root: Arc<ParkingLotRwLock<StateRoot>>,
    /// State version counter for optimistic concurrency control
    state_version: Arc<AtomicU64>,
    /// Default verification level
    default_verification_level: VerificationLevel,
    /// Chain ID (Avalanche C-Chain is 43114)
    chain_id: u64,
    /// Atomic executor for true atomicity guarantees
    atomic_executor: Option<Arc<AtomicExecutor>>,
    /// Parallel execution engine for high-throughput transaction processing
    parallel_engine: Option<Arc<ParallelExecutionEngine>>,
    /// Current execution mode
    execution_mode: ExecutionMode,
}

impl StatelessVM {
    /// Create a new instance of the stateless VM
    pub fn new(
        state_bundler: Arc<RwLock<StateBundler>>,
        security_verifier: Arc<dyn SecurityVerifier>,
        initial_state_root: StateRoot,
        initial_block_height: BlockHeight,
    ) -> Self {
        Self {
            block_height: Arc::new(AtomicU64::new(initial_block_height)),
            state_bundler,
            security_verifier,
            state_root: Arc::new(ParkingLotRwLock::new(initial_state_root)),
            state_version: Arc::new(AtomicU64::new(0)),
            default_verification_level: VerificationLevel::Standard,
            chain_id: 43114, // Avalanche C-Chain
            atomic_executor: None,
            parallel_engine: None,
            execution_mode: ExecutionMode::Coordinated,
        }
    }

    /// Execute a single transaction
    pub async fn execute_transaction(&mut self, transaction: Transaction) -> Result<TransactionStatus, VMError> {
        // Security verification step
        let verification_level = transaction.verification_level.unwrap_or(self.default_verification_level);
        let verification_result = self.security_verifier.verify_transaction(&transaction, verification_level).await?;
        
        if !verification_result.is_valid() {
            return Err(VMError::SecurityVerificationFailed { 
                reason: verification_result.failure_reason().unwrap_or("Unknown security violation").to_string() 
            });
        }

        // FIXED: Read state root safely
        let current_state_root = self.state_root.read().clone();
        let current_block_height = self.block_height.load(Ordering::SeqCst);
        
        // Create execution context
        let context = ExecutionContext::new(
            current_block_height,
            current_state_root,
            Arc::clone(&self.state_bundler),
        );

        // Execute the transaction
        let result = transaction.execute(context).await?;

        // FIXED: Update state root atomically if transaction was successful
        if result.is_success() {
            let mut state_root_lock = self.state_root.write();
            *state_root_lock = result.new_state_root().clone();
            self.state_version.fetch_add(1, Ordering::SeqCst);
        }

        Ok(result)
    }

    /// Execute a sequence of transactions atomically
    pub async fn execute_sequence(&mut self, sequence: TransactionSequence) -> Result<Vec<TransactionStatus>, VMError> {
        // Verify the entire sequence
        let verification_level = sequence.verification_level.unwrap_or(self.default_verification_level);
        let verification_result = self.security_verifier.verify_sequence(&sequence, verification_level).await?;
        
        if !verification_result.is_valid() {
            return Err(VMError::SecurityVerificationFailed { 
                reason: verification_result.failure_reason().unwrap_or("Unknown security violation").to_string() 
            });
        }
        
        // FIXED: Read state root safely
        let current_state_root = self.state_root.read().clone();
        let current_block_height = self.block_height.load(Ordering::SeqCst);
        
        // Create execution context
        let context = ExecutionContext::new(
            current_block_height,
            current_state_root,
            Arc::clone(&self.state_bundler),
        );
        
        // Execute the sequence
        let results = sequence.execute(context).await?;
        
        // FIXED: Update state root atomically if entire sequence was successful
        if results.iter().all(|r| r.is_success()) {
            if let Some(last_result) = results.last() {
                let mut state_root_lock = self.state_root.write();
                *state_root_lock = last_result.new_state_root().clone();
                self.state_version.fetch_add(1, Ordering::SeqCst);
            }
        }
        
        Ok(results)
    }

    /// Analyze the state requirements for a transaction
    pub async fn analyze_state_requirements(&self, transaction: &Transaction) -> Result<Vec<StateRequirement>, VMError> {
        let state_bundler = self.state_bundler.read().await;
        state_bundler.analyze_transaction(transaction).await
    }

    /// Analyze the state requirements for a transaction sequence
    pub async fn analyze_sequence_requirements(&self, sequence: &TransactionSequence) -> Result<Vec<StateRequirement>, VMError> {
        let state_bundler = self.state_bundler.read().await;
        state_bundler.analyze_sequence(sequence).await
    }

    /// Bundle state with a transaction to make it self-contained
    pub async fn bundle_transaction(&self, mut transaction: Transaction) -> Result<Transaction, VMError> {
        let requirements = self.analyze_state_requirements(&transaction).await?;
        let state_bundler = self.state_bundler.read().await;
        
        for requirement in requirements {
            let state_data = state_bundler.fetch_state(&requirement).await
                .map_err(|_| VMError::MissingState { 
                    address: requirement.address, 
                    key: format!("{:?}", requirement.key),
                    description: "Required state not available".into()
                })?;
            
            transaction.add_state(requirement, state_data);
        }
        
        Ok(transaction)
    }

    /// Bundle state with a transaction sequence to make it self-contained
    pub async fn bundle_sequence(&self, mut sequence: TransactionSequence) -> Result<TransactionSequence, VMError> {
        let requirements = self.analyze_sequence_requirements(&sequence).await?;
        let state_bundler = self.state_bundler.read().await;
        
        for requirement in requirements {
            let state_data = state_bundler.fetch_state(&requirement).await
                .map_err(|_| VMError::MissingState { 
                    address: requirement.address, 
                    key: format!("{:?}", requirement.key),
                    description: "Required state not available".into()
                })?;
            
            sequence.add_state(requirement, state_data);
        }
        
        Ok(sequence)
    }

    /// Set the default verification level for transactions
    pub fn set_default_verification_level(&mut self, level: VerificationLevel) {
        self.default_verification_level = level;
    }

    /// Get the current block height
    pub fn block_height(&self) -> BlockHeight {
        self.block_height.load(Ordering::SeqCst)
    }

    /// Get the current state root
    pub fn state_root(&self) -> StateRoot {
        self.state_root.read().clone()
    }

    /// Update the block height
    pub fn update_block_height(&mut self, new_height: BlockHeight) {
        self.block_height.store(new_height, Ordering::SeqCst);
    }
    
    /// Set the chain ID (Avalanche C-Chain is 43114)
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }
    
    /// Get the current chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    
    /// Execute a transaction sequence generated by an agent
    pub async fn execute_agent_actions(
        &mut self,
        agent: Box<dyn AgentInterface>,
        context: AgentContext,
        agent_address: Address,
    ) -> Result<Vec<TransactionStatus>, VMError> {
        // Create agent handler
        let handler = AgentHandler::new(agent, context, agent_address);
        
        // Plan and generate transaction sequence
        let sequence = handler.plan_and_execute().await?;
        
        // Execute the sequence
        self.execute_sequence(sequence).await
    }
    
    /// Verify a transaction sequence without executing it
    pub async fn verify_sequence(
        &self,
        sequence: &TransactionSequence,
    ) -> Result<VerificationResult, VMError> {
        let verification_level = sequence.verification_level.unwrap_or(self.default_verification_level);
        let result = self.security_verifier.verify_sequence(sequence, verification_level).await?;
        Ok(result)
    }
    
    /// Verify a transaction without executing it
    pub async fn verify_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<VerificationResult, VMError> {
        let verification_level = transaction.verification_level.unwrap_or(self.default_verification_level);
        let result = self.security_verifier.verify_transaction(transaction, verification_level).await?;
        Ok(result)
    }
    
    /// Create a self-contained transaction that includes all required state
    pub async fn create_self_contained_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<Transaction, VMError> {
        self.bundle_transaction(transaction).await
    }
    
    /// Create a self-contained transaction sequence that includes all required state
    pub async fn create_self_contained_sequence(
        &self,
        sequence: TransactionSequence,
    ) -> Result<TransactionSequence, VMError> {
        self.bundle_sequence(sequence).await
    }

    // ATOMIC EXECUTION METHODS

    /// Set the atomic executor for true atomicity guarantees
    pub fn set_atomic_executor(&mut self, executor: Arc<AtomicExecutor>) {
        self.atomic_executor = Some(executor);
    }

    /// Set the execution mode
    pub fn set_execution_mode(&mut self, mode: ExecutionMode) {
        self.execution_mode = mode;
    }

    /// Get the current execution mode
    pub fn execution_mode(&self) -> ExecutionMode {
        self.execution_mode
    }

    /// Execute transaction sequence with current execution mode
    pub async fn execute_with_mode(
        &mut self,
        sequence: TransactionSequence,
    ) -> Result<ExecutionResult, VMError> {
        match self.execution_mode {
            ExecutionMode::Coordinated => {
                let statuses = self.execute_sequence(sequence).await?;
                Ok(ExecutionResult::Coordinated(statuses))
            }
            ExecutionMode::Atomic => {
                let result = self.execute_atomic_sequence(sequence).await?;
                Ok(ExecutionResult::Atomic(result))
            }
            ExecutionMode::VerifiedAtomic => {
                let result = self.execute_verified_atomic_sequence(sequence).await?;
                Ok(ExecutionResult::VerifiedAtomic(result))
            }
            ExecutionMode::Parallel => {
                let result = self.execute_parallel_sequence(sequence).await?;
                Ok(ExecutionResult::Parallel(result))
            }
        }
    }

    /// Execute transaction sequence atomically
    pub async fn execute_atomic_sequence(
        &self,
        sequence: TransactionSequence,
    ) -> Result<AtomicExecutionResult, VMError> {
        let executor = self.atomic_executor.as_ref()
            .ok_or_else(|| VMError::InvalidOperation { description: "Atomic executor not configured".to_string() })?;
        
        executor.execute_atomic(sequence).await
    }

    /// Execute transaction sequence atomically with PCC+PCD verification
    pub async fn execute_verified_atomic_sequence(
        &self,
        sequence: TransactionSequence,
    ) -> Result<VerifiedAtomicResult, VMError> {
        let executor = self.atomic_executor.as_ref()
            .ok_or_else(|| VMError::InvalidOperation { description: "Atomic executor not configured".to_string() })?;
        
        executor.execute_verified_atomic(sequence).await
    }

    /// Execute transaction sequence with MEV protection
    pub async fn execute_mev_protected_sequence(
        &self,
        sequence: TransactionSequence,
    ) -> Result<VerifiedAtomicResult, VMError> {
        let executor = self.atomic_executor.as_ref()
            .ok_or_else(|| VMError::InvalidOperation { description: "Atomic executor not configured".to_string() })?;
        
        executor.submit_private_atomic(sequence).await
    }

    // PARALLEL EXECUTION METHODS

    /// Set the parallel execution engine for high-performance transaction processing
    pub fn set_parallel_engine(&mut self, engine: Arc<ParallelExecutionEngine>) {
        self.parallel_engine = Some(engine);
    }

    /// Execute transaction sequence in parallel with automatic dependency resolution
    pub async fn execute_parallel_sequence(
        &self,
        sequence: TransactionSequence,
    ) -> Result<ParallelExecutionResult, VMError> {
        let engine = self.parallel_engine.as_ref()
            .ok_or_else(|| VMError::InvalidOperation { description: "Parallel execution engine not configured".to_string() })?;
        
        let base_context = ExecutionContext {
            block_height: self.block_height.load(Ordering::SeqCst),
            state_root: self.state_root.read().clone(),
            state_bundler: self.state_bundler.clone(),
        };
        
        engine.execute_parallel_sequence(&sequence, base_context).await
            .map_err(|e| VMError::InvalidOperation { description: e.to_string() })
    }

    /// Execute multiple transaction sequences in parallel for maximum throughput
    pub async fn execute_parallel_sequences(
        &self,
        sequences: Vec<TransactionSequence>,
    ) -> Result<Vec<ParallelExecutionResult>, VMError> {
        let engine = self.parallel_engine.as_ref()
            .ok_or_else(|| VMError::InvalidOperation { description: "Parallel execution engine not configured".to_string() })?;
        
        let base_context = ExecutionContext {
            block_height: self.block_height.load(Ordering::SeqCst),
            state_root: self.state_root.read().clone(),
            state_bundler: self.state_bundler.clone(),
        };
        
        let mut results = Vec::new();
        for sequence in sequences {
            let result = engine.execute_parallel_sequence(&sequence, base_context.clone()).await
                .map_err(|e| VMError::InvalidOperation { description: e.to_string() })?;
            results.push(result);
        }
        Ok(results)
    }

    /// Get parallel execution engine metrics for performance monitoring
    pub fn get_parallel_metrics(&self) -> Result<crate::parallel::ParallelExecutionMetrics, VMError> {
        let engine = self.parallel_engine.as_ref()
            .ok_or_else(|| VMError::InvalidOperation { description: "Parallel execution engine not configured".to_string() })?;
        
        Ok(engine.get_metrics())
    }
    
    // HELPER METHODS FOR THREAD-SAFE STATE ACCESS
    
    /// Get current state root safely
    pub fn get_state_root(&self) -> StateRoot {
        self.state_root.read().clone()
    }
    
    /// Get current state version (for monitoring conflicts)
    pub fn get_state_version(&self) -> u64 {
        self.state_version.load(Ordering::SeqCst)
    }
    
    /// Get current block height
    pub fn get_block_height(&self) -> BlockHeight {
        self.block_height.load(Ordering::SeqCst)
    }
    
    /// Advance block height atomically
    pub fn advance_block(&self) -> BlockHeight {
        self.block_height.fetch_add(1, Ordering::SeqCst) + 1
    }
    
    /// Get cache hit rate for monitoring performance
    pub async fn get_cache_hit_rate(&self) -> f64 {
        let bundler = self.state_bundler.read().await;
        bundler.cache_hit_rate()
    }
}

/// Result of execution with different modes
#[derive(Debug, Clone)]
pub enum ExecutionResult {
    Coordinated(Vec<TransactionStatus>),
    Atomic(AtomicExecutionResult),
    VerifiedAtomic(VerifiedAtomicResult),
    Parallel(ParallelExecutionResult),
}
