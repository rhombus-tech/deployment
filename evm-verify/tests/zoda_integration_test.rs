use evm_verify::block_execution::{TransactionProcessor, TransactionResult, BlockExecutionConfig};
use ethereum_types::{H256, U256};
use std::time::Duration;

#[tokio::test] 
async fn test_zoda_batch_proof_integration() {
    // Simple integration test to verify ZODA batch proof generation works
    let config = BlockExecutionConfig::default();
    
    let processor = TransactionProcessor::new(config).expect("Failed to create processor");
    
    // Create a simple transaction result
    let transaction_results = vec![TransactionResult {
        transaction_hash: H256::from_low_u64_be(1),
        success: true,
        gas_used: 21000,
        state_changes: Vec::new(),
        proof: None,
        execution_time: Duration::from_millis(10),
        dependencies: Vec::new(),
        error: None,
    }];
    
    // Test that generate_batch_proofs can be called without panic
    let result = processor.generate_batch_proofs(transaction_results).await;
    
    // Basic test - it should not panic and return some result
    assert!(result.is_ok(), "Batch proof generation should not panic");
    
    let results_with_proofs = result.unwrap();
    assert_eq!(results_with_proofs.len(), 1);
    
    println!("✅ ZODA batch proof integration test completed successfully!");
}
