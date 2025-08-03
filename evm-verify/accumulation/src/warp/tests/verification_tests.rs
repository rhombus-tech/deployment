use evm_verify::accumulation::warp::verification::{
    WarpVerificationStrategy, create_warp_verification_strategy, SecurityReport, SecurityWarning
};
use evm_verify::accumulation::warp::accumulation::{Accumulator, AccumulationProof};
use std::sync::Arc;

// Helper function to create test transaction data
fn create_test_transaction(valid: bool) -> Vec<u8> {
    if valid {
        // Valid transaction format
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    } else {
        // Invalid/empty transaction
        vec![]
    }
}

// Helper function to create test proof data
fn create_test_proof_data(valid: bool) -> Vec<u8> {
    if valid {
        // Simulated valid proof structure with mock commitment bytes
        let mut data = Vec::with_capacity(128);
        
        // Header
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Magic bytes
        data.extend_from_slice(&[0x00, 0x01]); // Version
        
        // Previous commitment (32 bytes)
        data.extend_from_slice(&[1u8; 32]);
        
        // Current commitment (32 bytes)
        data.extend_from_slice(&[2u8; 32]);
        
        // Proof data (variable length)
        data.extend_from_slice(&[0x42; 48]);
        
        data
    } else {
        // Invalid proof format
        vec![0xAA, 0xBB]
    }
}

#[tokio::test]
async fn test_verification_strategy_creation() {
    // Create a verification strategy with default parameters
    let strategy = create_warp_verification_strategy();
    
    // Check that it's properly initialized
    assert_eq!(strategy.security_param(), 128);
}

#[tokio::test]
async fn test_verification_valid_transaction() {
    // Create a verification strategy
    let strategy = create_warp_verification_strategy();
    
    // Create a valid transaction and proof
    let tx_data = create_test_transaction(true);
    let proof_data = create_test_proof_data(true);
    
    // Combine into a single payload
    let mut payload = tx_data.clone();
    payload.extend_from_slice(&proof_data);
    
    // Verify the transaction
    let result = strategy.verify_transaction(&payload, 2).await;
    
    // Check that verification succeeded
    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(report.passed);
    assert!(report.warnings.is_empty());
    assert!(report.verification_time_ms > 0);
}

#[tokio::test]
async fn test_verification_invalid_transaction() {
    // Create a verification strategy
    let strategy = create_warp_verification_strategy();
    
    // Create an invalid transaction
    let tx_data = create_test_transaction(false);
    let proof_data = create_test_proof_data(true);
    
    // Combine into a single payload
    let mut payload = tx_data;
    payload.extend_from_slice(&proof_data);
    
    // Verify the transaction
    let result = strategy.verify_transaction(&payload, 2).await;
    
    // Check that verification failed appropriately
    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(!report.passed);
    assert!(!report.warnings.is_empty());
    
    // Should contain a malformed transaction warning
    let has_malformed_warning = report.warnings.iter().any(|w| {
        matches!(w, SecurityWarning::MalformedTransaction(_))
    });
    assert!(has_malformed_warning);
}

#[tokio::test]
async fn test_verification_invalid_proof() {
    // Create a verification strategy
    let strategy = create_warp_verification_strategy();
    
    // Create a valid transaction but invalid proof
    let tx_data = create_test_transaction(true);
    let proof_data = create_test_proof_data(false);
    
    // Combine into a single payload
    let mut payload = tx_data;
    payload.extend_from_slice(&proof_data);
    
    // Verify the transaction
    let result = strategy.verify_transaction(&payload, 2).await;
    
    // Check that verification failed appropriately
    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(!report.passed);
    assert!(!report.warnings.is_empty());
    
    // Should contain an invalid proof warning
    let has_invalid_proof_warning = report.warnings.iter().any(|w| {
        matches!(w, SecurityWarning::InvalidProof(_))
    });
    assert!(has_invalid_proof_warning);
}

#[tokio::test]
async fn test_verification_sequence() {
    // Create a verification strategy
    let strategy = create_warp_verification_strategy();
    
    // Create multiple valid transactions and proofs
    let tx1_data = create_test_transaction(true);
    let proof1_data = create_test_proof_data(true);
    
    let tx2_data = create_test_transaction(true);
    let proof2_data = create_test_proof_data(true);
    
    // Create combined payloads
    let mut payload1 = tx1_data.clone();
    payload1.extend_from_slice(&proof1_data);
    
    let mut payload2 = tx2_data.clone();
    payload2.extend_from_slice(&proof2_data);
    
    // Verify the transaction sequence
    let tx_refs = vec![payload1.as_slice(), payload2.as_slice()];
    let result = strategy.verify_transaction_sequence(&tx_refs, 2).await;
    
    // Check that verification succeeded
    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(report.passed);
    assert!(report.verification_time_ms > 0);
}

#[tokio::test]
async fn test_cached_verification() {
    // Create a verification strategy
    let strategy = Arc::new(create_warp_verification_strategy());
    
    // Create a valid transaction and proof
    let tx_data = create_test_transaction(true);
    let proof_data = create_test_proof_data(true);
    
    // Combine into a single payload
    let mut payload = tx_data.clone();
    payload.extend_from_slice(&proof_data);
    
    // Verify the transaction first time
    let result1 = strategy.verify_transaction(&payload, 2).await;
    assert!(result1.is_ok());
    let report1 = result1.unwrap();
    
    // Verify again - should use cache
    let result2 = strategy.verify_transaction(&payload, 2).await;
    assert!(result2.is_ok());
    let report2 = result2.unwrap();
    
    // Both should pass but the second one should be faster
    assert!(report1.passed && report2.passed);
    assert!(report2.verification_time_ms <= report1.verification_time_ms);
}

#[tokio::test]
async fn test_different_security_levels() {
    // Create verification strategies with different security levels
    let strategy_low = WarpVerificationStrategy::new(64);
    let strategy_high = WarpVerificationStrategy::new(256);
    
    // Create a valid transaction and proof
    let tx_data = create_test_transaction(true);
    let proof_data = create_test_proof_data(true);
    
    // Combine into a single payload
    let mut payload = tx_data.clone();
    payload.extend_from_slice(&proof_data);
    
    // Verify with different security levels
    let result_low = strategy_low.verify_transaction(&payload, 1).await;
    let result_high = strategy_high.verify_transaction(&payload, 3).await;
    
    // Both should pass
    assert!(result_low.is_ok() && result_low.unwrap().passed);
    assert!(result_high.is_ok() && result_high.unwrap().passed);
    
    // The higher security level should take more time (usually)
    // Note: This is probabilistic and might not always hold in tests
}
