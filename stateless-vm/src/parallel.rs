use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore, mpsc};
use futures::future::{join_all, try_join_all};
use futures::stream::{FuturesUnordered, StreamExt};
use futures::executor;
use anyhow::Result;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use dashmap::DashMap;

use crate::errors::{VMError, Result as VMResult};
use crate::transaction::{Transaction, TransactionSequence, TransactionStatus, ExecutionContext};
use crate::types::{Address, StateRoot, TransactionId, BlockHeight, Gas};
use crate::state::{StateBundler, StateRequirement};
use sha3::{Digest, Keccak256};
use rlp;
use ethereum_types::{H256, U256};

/// High-performance parallel execution engine for StatelessVM transactions
/// This demonstrates the revolutionary scalability advantage of StatelessVM
#[derive(Debug)]
pub struct ParallelExecutionEngine {
    /// Maximum number of concurrent transactions
    max_concurrency: usize,
    /// Semaphore to control parallelism
    concurrency_limiter: Arc<Semaphore>,
    /// State conflict detector for dependency analysis
    conflict_detector: Arc<StateConflictDetector>,
    /// Performance metrics tracker
    metrics: Arc<RwLock<ExecutionMetrics>>,
    /// Thread pool for CPU-intensive operations
    thread_pool: rayon::ThreadPool,
}

/// Detects state conflicts between transactions for safe parallelization
#[derive(Debug)]
pub struct StateConflictDetector {
    /// Cache of address -> storage key dependencies
    dependency_cache: DashMap<Address, HashSet<H256>>,
    /// Read-write access patterns
    access_patterns: DashMap<TransactionId, AccessPattern>,
}

/// Access pattern for a transaction
#[derive(Debug, Clone)]
pub struct AccessPattern {
    /// Addresses read from
    reads: HashSet<Address>,
    /// Addresses written to
    writes: HashSet<Address>,
    /// Storage keys accessed
    storage_keys: HashMap<Address, HashSet<H256>>,
    /// Contract deployments
    deployments: HashSet<Address>,
}

/// Execution batch for parallel processing
#[derive(Debug)]
pub struct ExecutionBatch {
    /// Transactions that can execute in parallel
    parallel_transactions: Vec<Transaction>,
    /// Execution contexts for each transaction
    contexts: Vec<ExecutionContext>,
    /// Dependency graph edges
    dependencies: HashMap<usize, Vec<usize>>,
}

/// Result of parallel execution
#[derive(Debug, Clone)]
pub struct ParallelExecutionResult {
    /// Status of each transaction
    pub transaction_results: Vec<TransactionStatus>,
    /// Total execution time
    pub execution_time_ms: u64,
    /// Number of transactions executed in parallel
    pub parallel_count: usize,
    /// Throughput in transactions per second
    pub throughput_tps: f64,
    /// State root after all executions
    pub final_state_root: StateRoot,
    /// Gas usage statistics
    pub gas_stats: GasStatistics,
    /// Parallelization efficiency (0-1, higher is better)
    pub efficiency: f64,
}

/// Gas usage statistics
#[derive(Debug, Clone)]
pub struct GasStatistics {
    pub total_gas_used: U256,
    pub avg_gas_per_tx: U256,
    pub max_gas_per_tx: U256,
    pub min_gas_per_tx: U256,
}

/// Performance metrics for the parallel execution engine
#[derive(Debug, Default, Clone)]
pub struct ExecutionMetrics {
    /// Number of parallel batches executed
    pub parallel_batches: u64,
    /// Average batch size (transactions per batch)
    pub avg_batch_size: f64,
    /// Peak throughput in transactions per second
    pub peak_throughput: f64,
    /// Total execution time in milliseconds
    pub total_execution_time_ms: u64,
    /// Time spent on conflict detection in milliseconds
    pub conflict_detection_time_ms: u64,
    /// Time spent on state bundling in milliseconds
    pub state_bundling_time_ms: u64,
    /// Total number of transactions processed
    pub total_transactions: u64,
}

/// Type alias for public API compatibility
pub type ParallelExecutionMetrics = ExecutionMetrics;

/// Efficiency metrics for parallelization
#[derive(Debug, Clone)]
pub struct ParallelizationEfficiency {
    /// Ratio of parallel to sequential execution time (lower is better)
    pub speedup_ratio: f64,
    /// Resource utilization percentage (0-100)
    pub resource_utilization: f64,
    /// Conflict rate (0-1, lower is better)
    pub conflict_rate: f64,
}

impl ParallelExecutionEngine {
    /// Create a new parallel execution engine with default settings
    pub fn new() -> Self {
        Self::with_max_concurrency(None)
    }
    
    /// Create a new parallel execution engine with specific max concurrency
    pub fn with_max_concurrency(max_concurrency: impl Into<Option<usize>>) -> Self {
        let max_concurrency = max_concurrency.into().unwrap_or_else(|| {
            // Use 2x CPU cores for optimal performance
            (num_cpus::get() * 2).max(4).min(64)
        });
        
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_concurrency)
            .thread_name(|i| format!("stateless-vm-{}", i))
            .build()
            .expect("Failed to create thread pool");

        Self {
            max_concurrency,
            concurrency_limiter: Arc::new(Semaphore::new(max_concurrency)),
            conflict_detector: Arc::new(StateConflictDetector::new()),
            metrics: Arc::new(RwLock::new(ExecutionMetrics::default())),
            thread_pool,
        }
    }

    /// Execute a transaction sequence with maximum parallelization
    /// This is the core method that demonstrates StatelessVM's revolutionary advantage
    pub async fn execute_parallel_sequence(
        &self,
        sequence: &TransactionSequence,
        base_context: ExecutionContext,
    ) -> VMResult<ParallelExecutionResult> {
        let start_time = std::time::Instant::now();
        
        tracing::info!(
            "Starting parallel execution of {} transactions with max concurrency {}",
            sequence.transactions().len(),
            self.max_concurrency
        );

        // Step 1: Analyze dependencies and create execution batches
        let batches = self.create_execution_batches(sequence, &base_context).await?;
        
        tracing::info!("Created {} execution batches", batches.len());

        // Step 2: Execute batches in dependency order with maximum parallelism within each batch
        let mut all_results = Vec::new();
        let mut current_state_root = base_context.state_root.clone();
        let mut total_parallel_count = 0;

        for (batch_idx, batch) in batches.into_iter().enumerate() {
            tracing::debug!("Executing batch {} with {} transactions", batch_idx, batch.parallel_transactions.len());
            
            let batch_result = self.execute_batch(batch, current_state_root.clone()).await?;
            
            // Update state root with the final state from this batch
            if let Some(last_result) = batch_result.last() {
                current_state_root = last_result.new_state_root().clone();
            }
            
            total_parallel_count += batch_result.len();
            all_results.extend(batch_result);
        }

        let execution_time = start_time.elapsed();
        let execution_time_ms = execution_time.as_millis() as u64;
        
        // Calculate performance metrics
        let throughput_tps = if execution_time_ms > 0 {
            (all_results.len() as f64) / (execution_time_ms as f64 / 1000.0)
        } else {
            0.0
        };

        let gas_stats = self.calculate_gas_statistics(&all_results);
        let efficiency = self.calculate_parallelization_efficiency(&all_results, total_parallel_count);

        // Update global metrics
        self.update_metrics(&all_results, execution_time_ms, throughput_tps).await;

        tracing::info!(
            "Parallel execution completed: {} TPS, {:.2}% efficiency, {}ms total time",
            throughput_tps as u64,
            efficiency * 100.0,
            execution_time_ms
        );

        Ok(ParallelExecutionResult {
            transaction_results: all_results,
            execution_time_ms,
            parallel_count: total_parallel_count,
            throughput_tps,
            final_state_root: current_state_root,
            gas_stats,
            efficiency,
        })
    }

    /// Create execution batches that maximize parallelism while respecting dependencies
    async fn create_execution_batches(
        &self,
        sequence: &TransactionSequence,
        base_context: &ExecutionContext,
    ) -> VMResult<Vec<ExecutionBatch>> {
        let conflict_start = std::time::Instant::now();
        
        // Analyze all transactions for state conflicts
        let transactions = sequence.transactions();
        let mut access_patterns = Vec::new();
        
        // Use parallel analysis for large transaction sets
        if transactions.len() > 10 {
            access_patterns = self.thread_pool.install(|| {
                transactions
                    .par_iter()
                    .map(|tx| self.analyze_transaction_access_pattern(tx))
                    .collect::<Result<Vec<_>, _>>()
            })?;
        } else {
            for tx in transactions {
                access_patterns.push(self.analyze_transaction_access_pattern(tx)?);
            }
        }

        // Build dependency graph
        let dependency_graph = self.build_dependency_graph(&access_patterns);
        
        // Create batches using topological sort with parallelization optimization
        let batches = self.create_batches_from_dependencies(
            transactions,
            &dependency_graph,
            base_context,
        )?;

        let conflict_time = conflict_start.elapsed().as_millis() as u64;
        let mut metrics = self.metrics.write().await;
        metrics.conflict_detection_time_ms += conflict_time;

        Ok(batches)
    }

    /// Execute a single batch of non-conflicting transactions in parallel
    async fn execute_batch(
        &self,
        batch: ExecutionBatch,
        state_root: StateRoot,
    ) -> VMResult<Vec<TransactionStatus>> {
        let batch_size = batch.parallel_transactions.len();
        
        if batch_size == 1 {
            // Single transaction - execute directly
            let tx = &batch.parallel_transactions[0];
            let context = ExecutionContext {
                block_height: batch.contexts[0].block_height,
                state_root,
                state_bundler: Arc::clone(&batch.contexts[0].state_bundler),
            };
            
            let result = tx.execute(context).await?;
            return Ok(vec![result]);
        }

        // Multiple transactions - execute in parallel
        tracing::debug!("Executing {} transactions in parallel", batch_size);
        
        let mut futures = FuturesUnordered::new();
        
        for (i, tx) in batch.parallel_transactions.iter().enumerate() {
            let tx = tx.clone();
            let context = ExecutionContext {
                block_height: batch.contexts[i].block_height,
                state_root: state_root.clone(),
                state_bundler: Arc::clone(&batch.contexts[i].state_bundler),
            };
            
            let permit = Arc::clone(&self.concurrency_limiter);
            
            futures.push(async move {
                let _permit = permit.acquire().await.unwrap();
                let result = tx.execute(context).await;
                (i, result)
            });
        }

        // Collect results maintaining order
        let mut results = vec![None; batch_size];
        
        while let Some((index, result)) = futures.next().await {
            results[index] = Some(result?);
        }

        // Convert to final results vector
        let final_results: Vec<TransactionStatus> = results
            .into_iter()
            .map(|r| r.expect("All results should be populated"))
            .collect();

        Ok(final_results)
    }

    /// Analyze transaction for state access patterns
    fn analyze_transaction_access_pattern(&self, tx: &Transaction) -> VMResult<AccessPattern> {
        let mut pattern = AccessPattern {
            reads: HashSet::new(),
            writes: HashSet::new(),
            storage_keys: HashMap::new(),
            deployments: HashSet::new(),
        };

        // Analyze based on transaction type and bundled state
        if tx.to.map_or(true, |addr| addr == Address::zero()) {
            // Contract deployment
            let mut hasher = Keccak256::new();
            // Encode address and nonce separately for RLP
            let mut stream = rlp::RlpStream::new_list(2);
            stream.append(&tx.from.as_bytes());
            stream.append(&tx.nonce);
            hasher.update(&stream.out());
            let hash = hasher.finalize();
            let deployment_addr = Address::from_slice(&hash[12..]);
            pattern.deployments.insert(deployment_addr);
            pattern.writes.insert(deployment_addr);
        } else {
            // Regular transaction
            if let Some(to) = tx.to {
                pattern.reads.insert(to);
                if tx.value > U256::zero() || !tx.data.is_empty() {
                    pattern.writes.insert(to);
                }
            }
        }

        // Add sender as read (for nonce/balance check)
        pattern.reads.insert(tx.from);
        pattern.writes.insert(tx.from); // Nonce increment

        // Analyze bundled state requirements
        for req in tx.state_requirements() {
            pattern.reads.insert(req.address);
            
            pattern.storage_keys
                .entry(req.address)
                .or_insert_with(HashSet::new)
                .insert(req.key);
        }

        Ok(pattern)
    }

    /// Build dependency graph between transactions
    fn build_dependency_graph(&self, patterns: &[AccessPattern]) -> HashMap<usize, Vec<usize>> {
        let mut dependencies = HashMap::new();
        
        for (i, pattern_i) in patterns.iter().enumerate() {
            let mut deps = Vec::new();
            
            for (j, pattern_j) in patterns.iter().enumerate().take(i) {
                if self.has_conflict(pattern_j, pattern_i) {
                    deps.push(j);
                }
            }
            
            if !deps.is_empty() {
                dependencies.insert(i, deps);
            }
        }
        
        dependencies
    }

    /// Check if two access patterns conflict (read-write or write-write)
    fn has_conflict(&self, pattern_a: &AccessPattern, pattern_b: &AccessPattern) -> bool {
        // Write-Write conflicts
        if !pattern_a.writes.is_disjoint(&pattern_b.writes) {
            return true;
        }
        
        // Read-Write conflicts
        if !pattern_a.reads.is_disjoint(&pattern_b.writes) || 
           !pattern_a.writes.is_disjoint(&pattern_b.reads) {
            return true;
        }
        
        // Storage key conflicts
        for (addr, keys_a) in &pattern_a.storage_keys {
            if let Some(keys_b) = pattern_b.storage_keys.get(addr) {
                if !keys_a.is_disjoint(keys_b) {
                    return true;
                }
            }
        }
        
        // Deployment conflicts
        if !pattern_a.deployments.is_disjoint(&pattern_b.deployments) {
            return true;
        }
        
        false
    }

    /// Create execution batches from dependency graph using advanced algorithms
    fn create_batches_from_dependencies(
        &self,
        transactions: &[Transaction],
        dependencies: &HashMap<usize, Vec<usize>>,
        base_context: &ExecutionContext,
    ) -> VMResult<Vec<ExecutionBatch>> {
        let mut batches = Vec::new();
        let mut remaining: HashSet<usize> = (0..transactions.len()).collect();
        
        while !remaining.is_empty() {
            let mut current_batch = Vec::new();
            let mut current_contexts = Vec::new();
            let mut batch_dependencies = HashMap::new();
            
            // Find all transactions with no remaining dependencies
            let ready: Vec<usize> = remaining
                .iter()
                .filter(|&&i| {
                    dependencies
                        .get(&i)
                        .map_or(true, |deps| deps.iter().all(|&dep| !remaining.contains(&dep)))
                })
                .cloned()
                .collect();
            
            // Add ready transactions to current batch
            for &tx_idx in &ready {
                current_batch.push(transactions[tx_idx].clone());
                current_contexts.push(base_context.clone());
                
                if let Some(deps) = dependencies.get(&tx_idx) {
                    batch_dependencies.insert(current_batch.len() - 1, deps.clone());
                }
                
                remaining.remove(&tx_idx);
            }
            
            if current_batch.is_empty() {
                return Err(VMError::Internal {
                    description: "Circular dependency detected in transaction sequence".to_string(),
                });
            }
            
            batches.push(ExecutionBatch {
                parallel_transactions: current_batch,
                contexts: current_contexts,
                dependencies: batch_dependencies,
            });
        }
        
        Ok(batches)
    }

    /// Calculate gas usage statistics
    fn calculate_gas_statistics(&self, results: &[TransactionStatus]) -> GasStatistics {
        if results.is_empty() {
            return GasStatistics {
                total_gas_used: U256::zero(),
                avg_gas_per_tx: U256::zero(),
                max_gas_per_tx: U256::zero(),
                min_gas_per_tx: U256::zero(),
            };
        }

        let gas_values: Vec<U256> = results.iter().map(|r| r.gas_used).collect();
        let total_gas_used = gas_values.iter().fold(U256::zero(), |acc, &gas| acc + gas);
        let avg_gas_per_tx = total_gas_used / U256::from(results.len());
        let max_gas_per_tx = gas_values.iter().max().cloned().unwrap_or(U256::zero());
        let min_gas_per_tx = gas_values.iter().min().cloned().unwrap_or(U256::zero());

        GasStatistics {
            total_gas_used,
            avg_gas_per_tx,
            max_gas_per_tx,
            min_gas_per_tx,
        }
    }

    /// Calculate parallelization efficiency (how much parallelism was achieved)
    fn calculate_parallelization_efficiency(&self, results: &[TransactionStatus], parallel_count: usize) -> f64 {
        if results.is_empty() {
            return 0.0;
        }
        
        // Efficiency = actual parallel executions / total transactions
        (parallel_count as f64) / (results.len() as f64)
    }

    /// Update performance metrics
    async fn update_metrics(&self, results: &[TransactionStatus], execution_time_ms: u64, throughput_tps: f64) {
        let mut metrics = self.metrics.write().await;
        
        metrics.total_transactions += results.len() as u64;
        metrics.parallel_batches += 1;
        metrics.avg_batch_size = (metrics.avg_batch_size * (metrics.parallel_batches - 1) as f64 + results.len() as f64) / metrics.parallel_batches as f64;
        metrics.peak_throughput = metrics.peak_throughput.max(throughput_tps);
        metrics.total_execution_time_ms += execution_time_ms;
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> ExecutionMetrics {
        executor::block_on(self.metrics.read()).clone()
    }

    /// Benchmark parallel execution performance
    pub async fn benchmark_performance(
        &self,
        test_transactions: Vec<Transaction>,
        context: ExecutionContext,
    ) -> VMResult<ParallelExecutionResult> {
        let sequence = crate::transaction::TransactionSequence::new(test_transactions, false);
        self.execute_parallel_sequence(&sequence, context).await
    }
}

impl StateConflictDetector {
    pub fn new() -> Self {
        Self {
            dependency_cache: DashMap::new(),
            access_patterns: DashMap::new(),
        }
    }
}

/// Helper function to calculate keccak256 hash
fn keccak256(input: &[u8]) -> H256 {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(input);
    H256::from_slice(&hasher.finalize())
}
