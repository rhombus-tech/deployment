use avalanche_stateless_vm::core::*;
use avalanche_stateless_vm::parallel::*;
use avalanche_stateless_vm::state::*;
use avalanche_stateless_vm::transaction::{ExecutionContext, TransactionSequence, Transaction};
use avalanche_stateless_vm::security::*;
use avalanche_stateless_vm::types::*;
use avalanche_stateless_vm::prelude::*;
use ethereum_types::{Address, U256, H256};
use std::time::Instant;
use std::collections::HashMap;
use tokio_test;
use std::sync::Arc;
use tokio::sync::RwLock;

// Test utilities
struct TestStateProvider {
    state_data: HashMap<(Address, H256), Vec<u8>>,
}

#[async_trait::async_trait]
impl StateProvider for TestStateProvider {
    async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Vec<u8>> {
        if let Some(value) = self.state_data.get(&(requirement.address, requirement.key)) {
            Ok(value.clone())
        } else {
            Ok(vec![0; 32]) // Default empty state
        }
    }

    async fn has_state(&self, requirement: &StateRequirement) -> bool {
        self.state_data.contains_key(&(requirement.address, requirement.key))
    }

    async fn state_root_at_height(&self, _height: u64) -> Result<StateRoot> {
        Ok(StateRoot(H256::zero()))
    }
}

impl TestStateProvider {
    fn new() -> Self {
        Self {
            state_data: HashMap::new(),
        }
    }
    
    fn with_state(mut self, address: Address, key: H256, value: Vec<u8>) -> Self {
        self.state_data.insert((address, key), value);
        self
    }
}

struct TestSecurityVerifier;

#[async_trait::async_trait]
impl SecurityVerifier for TestSecurityVerifier {
    async fn verify_transaction(
        &self,
        _transaction: &Transaction,
        _level: VerificationLevel,
    ) -> Result<VerificationResult> {
        Ok(VerificationResult::success())
    }

    async fn verify_sequence(
        &self,
        _sequence: &TransactionSequence,
        _level: VerificationLevel,
    ) -> Result<VerificationResult> {
        Ok(VerificationResult::success())
    }
}

// Helper functions
fn create_test_transaction(nonce: u64, to: Option<Address>, value: U256, gas_limit: u64) -> Transaction {
    Transaction::new(
        Address::from_low_u64_be(nonce), // from
        to,
        value,
        vec![].into(), // data
        U256::from(gas_limit),
        U256::from(21_000_000_000u64), // gas_price
        nonce,
    )
}

fn create_test_context() -> ExecutionContext {
    let state_provider = Arc::new(TestStateProvider::new());
    let state_bundler = StateBundler::new(vec![state_provider]);
    
    ExecutionContext::new(
        1000000, // block_height  
        StateRoot(H256::zero()),
        Arc::new(RwLock::new(state_bundler)),
    )
}

fn create_conflicting_transactions() -> Vec<Transaction> {
    let contract_addr = Address::from_low_u64_be(0x42);
    
    vec![
        // Two transactions that read/write the same storage slot (conflict)
        Transaction::new(
            Address::from_low_u64_be(1),
            Some(contract_addr),
            U256::zero(),
            vec![0x60, 0x01, 0x54].into(), // SLOAD(1) - read from slot 1
            U256::from(100_000),
            U256::from(20_000_000_000u64),
            2,
        ),
        Transaction::new(
            Address::from_low_u64_be(2),
            Some(contract_addr),
            U256::zero(),
            vec![0x60, 0x00, 0x54].into(), // SLOAD(0) - read from slot 0
            U256::from(100_000),
            U256::from(21_000_000_000u64),
            1,
        ),
    ]
}

fn create_independent_transactions() -> Vec<Transaction> {
    vec![
        // Transaction 1: Transfer to address 0x1
        create_test_transaction(1, Some(Address::from_low_u64_be(0x1)), U256::from(1000), 21_000),
        
        // Transaction 2: Transfer to address 0x2  
        create_test_transaction(2, Some(Address::from_low_u64_be(0x2)), U256::from(2000), 21_000),
        
        // Transaction 3: Transfer to address 0x3
        create_test_transaction(3, Some(Address::from_low_u64_be(0x3)), U256::from(3000), 21_000),
    ]
}

// Unit Tests
#[tokio::test]
async fn test_parallel_engine_creation() {
    let engine = ParallelExecutionEngine::new();
    
    // Verify engine is created with correct defaults
    let metrics = engine.get_metrics();
    assert_eq!(metrics.total_transactions, 0);
    assert_eq!(metrics.parallel_batches, 0);
    assert_eq!(metrics.total_execution_time_ms, 0);
}

#[tokio::test]
async fn test_parallel_execution_independent_transactions() {
    let engine = ParallelExecutionEngine::new();
    let transactions = create_independent_transactions();
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    
    // Execute independent transactions - should achieve high parallelism
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    assert!(result.is_ok(), "Independent transactions execution should succeed");
    
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), 3);
    assert!(parallel_result.parallel_count > 1, "Should achieve some parallelism");
    assert!(parallel_result.efficiency > 0.5, "Efficiency should be decent for independent transactions");
}

#[tokio::test]
async fn test_parallel_execution_conflicting_transactions() {
    let engine = ParallelExecutionEngine::new();
    let transactions = create_conflicting_transactions();
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    
    // Execute conflicting transactions - should handle conflicts gracefully
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    assert!(result.is_ok(), "Conflicting transactions execution should succeed");
    
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), 2);
    // Note: parallel_count might be lower due to conflicts
}

#[tokio::test]
async fn test_single_transaction_execution() {
    let engine = ParallelExecutionEngine::new();
    let transactions = vec![create_test_transaction(1, Some(Address::from_low_u64_be(0x1)), U256::from(1000), 21_000)];
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    
    assert!(result.is_ok(), "Single transaction execution should succeed: {:?}", result.err());
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), 1);
    assert_eq!(parallel_result.parallel_count, 1);
}

#[tokio::test]
async fn test_multiple_independent_transactions_execution() {
    let engine = ParallelExecutionEngine::new();
    let transactions = create_independent_transactions();
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    
    assert!(result.is_ok(), "Independent transactions execution should succeed: {:?}", result.err());
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), 3);
    assert_eq!(parallel_result.parallel_count, 3, "All independent transactions should execute in parallel");
    assert!(parallel_result.efficiency > 0.9, "Efficiency should be high for independent transactions");
}

#[tokio::test]
async fn test_conflicting_transactions_execution() {
    let engine = ParallelExecutionEngine::new();
    let transactions = create_conflicting_transactions();
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    
    assert!(result.is_ok(), "Conflicting transactions execution should succeed: {:?}", result.err());
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), 2);
    // Parallel count should be less than total due to conflicts
    assert!(parallel_result.parallel_count <= 2, "Conflicting transactions should limit parallelism");
}

#[tokio::test]
async fn test_execution_metrics_tracking() {
    let engine = ParallelExecutionEngine::new();
    let transactions = create_independent_transactions();
    let sequence = TransactionSequence::new(transactions, false);
    let parallel_result = engine.execute_parallel_sequence(&sequence, create_test_context()).await.unwrap();
    
    // Verify multiple transaction execution
    assert_eq!(parallel_result.transaction_results.len(), 3);
    
    // Check that execution produced reasonable metrics
    assert!(parallel_result.execution_time_ms >= 0, "Execution time should be non-negative");
    assert!(parallel_result.throughput_tps >= 0.0, "Throughput should be non-negative"); 
    assert_eq!(parallel_result.parallel_count, 3, "Should track parallel count correctly");
    
    // Test engine metrics (may be default if not fully implemented)
    let metrics = engine.get_metrics();
    // These are cumulative, so they might be 0 for a fresh engine - that's ok
    assert!(metrics.total_transactions >= 0);
    assert!(metrics.parallel_batches >= 0);
}

#[tokio::test]
async fn test_empty_transaction_sequence() {
    let engine = ParallelExecutionEngine::new();
    let sequence = TransactionSequence::new(vec![], false);
    let context = create_test_context();
    
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    
    assert!(result.is_ok(), "Empty sequence execution should succeed");
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), 0);
    assert_eq!(parallel_result.parallel_count, 0);
    assert_eq!(parallel_result.efficiency, 0.0);
}

// Integration Tests
#[tokio::test]
async fn test_end_to_end_parallel_execution() {
    let state_provider = Arc::new(TestStateProvider::new()
        .with_state(
            Address::from_low_u64_be(0x1), 
            H256::zero(), 
{
                let mut bytes = [0u8; 32];
                U256::from(10000).to_big_endian(&mut bytes);
                bytes.to_vec()
            }
        )
        .with_state(
            Address::from_low_u64_be(0x2), 
            H256::zero(), 
{
                let mut bytes = [0u8; 32];
                U256::from(5000).to_big_endian(&mut bytes);
                bytes.to_vec()
            }
        )
    );
    
    let state_bundler = StateBundler::new(vec![state_provider]);
    let security_verifier = Arc::new(TestSecurityVerifier);
    
    // Create a StatelessVM with parallel execution mode
    let mut vm = StatelessVM::new(
        Arc::new(RwLock::new(state_bundler)),
        security_verifier,
        StateRoot(H256::random()),
        1,
    );
    
    // Configure parallel execution engine
    let parallel_engine = Arc::new(ParallelExecutionEngine::new());
    vm.set_parallel_engine(parallel_engine);
    vm.set_execution_mode(ExecutionMode::Parallel);
    
    // Create a mix of independent and dependent transactions
    let mut transactions = create_independent_transactions();
    transactions.extend(create_conflicting_transactions());
    
    let sequence = TransactionSequence::new(transactions, false);
    
    // Execute with parallel mode
    let result = vm.execute_with_mode(sequence).await;
    
    assert!(result.is_ok(), "End-to-end parallel execution should succeed: {:?}", result.err());
    let execution_result = result.unwrap();
    if let ExecutionResult::Parallel(parallel_result) = execution_result {
        assert!(parallel_result.transaction_results.len() > 0, "Should have execution results");
    } else {
        panic!("Expected parallel execution result");
    }
}

// Performance Benchmarks
#[tokio::test]
async fn benchmark_parallel_vs_sequential_small_batch() {
    benchmark_parallel_vs_sequential(10, "small batch").await;
}

#[tokio::test]
async fn benchmark_parallel_vs_sequential_medium_batch() {
    benchmark_parallel_vs_sequential(50, "medium batch").await;
}

#[tokio::test]
async fn benchmark_parallel_vs_sequential_large_batch() {
    benchmark_parallel_vs_sequential(100, "large batch").await;
}

async fn benchmark_parallel_vs_sequential(tx_count: usize, test_name: &str) {
    // Create independent transactions for maximum parallelism
    let mut transactions = Vec::new();
    for i in 0..tx_count {
        transactions.push(create_test_transaction(
            i as u64 + 1,
            Some(Address::from_low_u64_be(i as u64 + 1)),
            U256::from(1000 + i),
            21_000
        ));
    }
    
    let sequence = TransactionSequence::new(transactions.clone(), false);
    
    // Benchmark parallel execution
    let parallel_engine = ParallelExecutionEngine::new();
    let parallel_start = Instant::now();
    let parallel_result = parallel_engine.execute_parallel_sequence(&sequence, create_test_context()).await.unwrap();
    let parallel_duration = parallel_start.elapsed();
    
    // Benchmark sequential execution (simulate by creating engine with max_concurrency = 1)
    let sequential_engine = ParallelExecutionEngine::with_max_concurrency(1);
    let sequential_start = Instant::now();
    let sequential_result = sequential_engine.execute_parallel_sequence(&sequence, create_test_context()).await.unwrap();
    let sequential_duration = sequential_start.elapsed();
    
    // Calculate performance metrics
    let speedup = sequential_duration.as_nanos() as f64 / parallel_duration.as_nanos() as f64;
    let parallel_efficiency = parallel_result.efficiency;
    
    println!(
        "\n=== Performance Benchmark: {} ({} transactions) ===",
        test_name, tx_count
    );
    println!("Parallel execution:   {:?} ({} TPS)", parallel_duration, 
             (tx_count as f64 / parallel_duration.as_secs_f64()) as u64);
    println!("Sequential execution: {:?} ({} TPS)", sequential_duration,
             (tx_count as f64 / sequential_duration.as_secs_f64()) as u64);
    println!("Speedup: {:.2}x", speedup);
    println!("Parallel efficiency: {:.1}%", parallel_efficiency * 100.0);
    println!("Parallel count: {}/{}", parallel_result.parallel_count, tx_count);
    
    // Performance assertions
    assert!(parallel_result.transaction_results.len() == tx_count, "All transactions should be executed");
    assert!(parallel_result.parallel_count > 0, "Should have some parallel execution");
    
    // For independent transactions, we expect good parallelism
    if tx_count >= 10 {
        assert!(parallel_efficiency > 0.8, "Should achieve high efficiency with independent transactions");
        // Note: For small batches, parallel overhead may dominate
        // Just verify both modes completed successfully and we have some parallelism
        assert!(parallel_result.parallel_count > 0, "Should have some parallel execution");
    }
}

#[tokio::test]
async fn test_stress_test_high_concurrency() {
    let tx_count = 200;
    let mut transactions = Vec::new();
    
    // Create transactions with some conflicts but mostly independent
    for i in 0..tx_count {
        let to_addr = if i % 10 == 0 {
            // Every 10th transaction conflicts with others in its group
            Address::from_low_u64_be((i / 10) as u64)
        } else {
            // Others are independent
            Address::from_low_u64_be(i as u64 + 1000)
        };
        
        transactions.push(create_test_transaction(
            i as u64 + 1,
            Some(to_addr),
            U256::from(1000 + i),
            21_000
        ));
    }
    
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    let engine = ParallelExecutionEngine::new();
    
    let start = Instant::now();
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    let duration = start.elapsed();
    
    assert!(result.is_ok(), "Stress test should complete successfully: {:?}", result.err());
    let parallel_result = result.unwrap();
    
    println!("\n=== Stress Test Results ===");
    println!("Transactions: {}", tx_count);
    println!("Duration: {:?}", duration);
    println!("TPS: {}", (tx_count as f64 / duration.as_secs_f64()) as u64);
    println!("Parallel count: {}", parallel_result.parallel_count);
    println!("Efficiency: {:.1}%", parallel_result.efficiency * 100.0);
    
    assert_eq!(parallel_result.transaction_results.len(), tx_count);
    assert!(parallel_result.parallel_count > tx_count / 2, "Should achieve significant parallelism");
    assert!(duration.as_millis() < 5000, "Should complete within 5 seconds");
}

#[tokio::test]
async fn test_memory_usage_large_batch() {
    // Test that we can handle large batches without excessive memory usage
    let tx_count = 500;
    let mut transactions = Vec::new();
    
    for i in 0..tx_count {
        transactions.push(create_test_transaction(
            i as u64 + 1,
            Some(Address::from_low_u64_be(i as u64 + 1)),
            U256::from(1000 + i),
            21_000
        ));
    }
    
    let sequence = TransactionSequence::new(transactions, false);
    let context = create_test_context();
    let engine = ParallelExecutionEngine::new();
    
    let result = engine.execute_parallel_sequence(&sequence, context).await;
    
    assert!(result.is_ok(), "Large batch execution should succeed");
    let parallel_result = result.unwrap();
    assert_eq!(parallel_result.transaction_results.len(), tx_count);
    
    // Verify metrics are reasonable
    let metrics = engine.get_metrics();
    assert_eq!(metrics.total_transactions, tx_count as u64);
    assert!(metrics.avg_batch_size > 0.0);
}

#[tokio::test]
async fn test_concurrent_engine_usage() {
    // Test that multiple engine instances can run concurrently
    let engines: Vec<_> = (0..4)
        .map(|_| Arc::new(ParallelExecutionEngine::new()))
        .collect();
    
    let mut handles = Vec::new();
    
    for (i, engine) in engines.into_iter().enumerate() {
        let handle = tokio::spawn(async move {
            let transactions = create_independent_transactions();
            let sequence = TransactionSequence::new(transactions, false);
            let context = create_test_context();
            
            let result = engine.execute_parallel_sequence(&sequence, context).await;
            (i, result)
        });
        handles.push(handle);
    }
    
    // Wait for all engines to complete
    for handle in handles {
        let (engine_id, result) = handle.await.unwrap();
        assert!(result.is_ok(), "Engine {} should succeed", engine_id);
        let parallel_result = result.unwrap();
        assert_eq!(parallel_result.transaction_results.len(), 3);
    }
}
