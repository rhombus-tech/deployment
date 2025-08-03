use evm_verify::accumulation::warp::field::WarpField;
use evm_verify::accumulation::warp::verification::create_warp_verification_strategy;
use evm_verify::accumulation::warp::integration::{create_warp_context, verify_with_warp};
use stateless_vm::pcd::PCDSecurityVerifier;
use stateless_vm::transaction::{Transaction, TransactionBuilder};
use stateless_vm::security::{SecurityVerifier, VerificationLevel};
use std::sync::Arc;

// Helper to create a test transaction
fn create_test_transaction() -> Transaction {
    TransactionBuilder::default()
        .with_sender([1; 20])
        .with_receiver([2; 20])
        .with_amount(100)
        .with_nonce(1)
        .with_data(vec![3, 4, 5])
        .build()
        .expect("Failed to build transaction")
}

#[tokio::test]
async fn test_warp_stateless_vm_integration() {
    // Create a PCDSecurityVerifier with WARP enabled
    let verifier = PCDSecurityVerifier::new_with_warp_params(128);
    
    // Create a test transaction
    let transaction = create_test_transaction();
    
    // Verify transaction with WARP
    let result = verifier.verify_transaction(
        &transaction, 
        VerificationLevel::Standard
    ).await;
    
    // The verification should succeed
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    let verification_result = result.unwrap();
    
    // Check the result
    assert!(verification_result.is_passed(), "Verification did not pass");
    
    // Check that metrics contain WARP-specific fields
    let metrics = verification_result.metrics();
    assert!(metrics.is_some(), "No metrics in result");
    
    let metrics_str = metrics.unwrap();
    assert!(metrics_str.contains("warp_enabled"), "WARP metrics not present");
    assert!(metrics_str.contains("cryptographic_scheme"), "Crypto scheme not in metrics");
}

#[tokio::test]
async fn test_direct_warp_verification() {
    // Create a WARP verification strategy
    let warp_strategy = create_warp_verification_strategy();
    let context = Arc::new(warp_strategy);
    
    // Create a test transaction and encode it
    let transaction = create_test_transaction();
    let tx_bytes = transaction.encode().expect("Failed to encode transaction");
    
    // Manual verification through WARP
    let result = verify_with_warp(
        context,
        |ctx, data, level| async move {
            ctx.verify_transaction(data, level).await
        },
        &tx_bytes,
        2 // Standard level
    ).await;
    
    // Should succeed
    assert!(result.is_ok(), "WARP verification failed: {:?}", result.err());
    let report = result.unwrap();
    assert!(report.passed, "Verification did not pass");
}

#[tokio::test]
async fn test_warp_transaction_sequence() {
    // Create a PCDSecurityVerifier with WARP enabled
    let verifier = PCDSecurityVerifier::new_with_warp_params(128);
    
    // Create a sequence of test transactions
    let transaction1 = create_test_transaction();
    let transaction2 = TransactionBuilder::default()
        .with_sender([3; 20])
        .with_receiver([4; 20])
        .with_amount(200)
        .with_nonce(2)
        .build()
        .expect("Failed to build transaction");
    
    // Create a transaction sequence
    let sequence = stateless_vm::transaction::TransactionSequence::new(
        vec![transaction1, transaction2]
    );
    
    // Verify sequence with WARP
    let result = verifier.verify_sequence(
        &sequence, 
        VerificationLevel::Standard
    ).await;
    
    // The verification should succeed
    assert!(result.is_ok(), "Sequence verification failed: {:?}", result.err());
    let verification_result = result.unwrap();
    
    // Check the result
    assert!(verification_result.is_passed(), "Verification did not pass");
}

#[tokio::test]
async fn test_compare_standard_and_warp_verification() {
    // Create both standard and WARP verifiers
    let standard_verifier = PCDSecurityVerifier::new(
        stateless_vm::pcd::VerificationStrategy::Groth16, 
        false
    );
    
    let warp_verifier = PCDSecurityVerifier::new_with_warp_params(128);
    
    // Create a test transaction
    let transaction = create_test_transaction();
    
    // Verify with standard verifier
    let standard_result = standard_verifier.verify_transaction(
        &transaction, 
        VerificationLevel::Standard
    ).await;
    
    // Verify with WARP verifier
    let warp_result = warp_verifier.verify_transaction(
        &transaction, 
        VerificationLevel::Standard
    ).await;
    
    // Both verifications should succeed
    assert!(standard_result.is_ok() && warp_result.is_ok(), 
           "Verification failed: standard={:?}, warp={:?}", 
           standard_result.err(), warp_result.err());
    
    let std_verification = standard_result.unwrap();
    let warp_verification = warp_result.unwrap();
    
    // Both should pass
    assert!(std_verification.is_passed() && warp_verification.is_passed(),
           "Verification did not pass: standard={}, warp={}", 
           std_verification.is_passed(), warp_verification.is_passed());
    
    // Only WARP should have specific metrics
    let warp_metrics = warp_verification.metrics().unwrap_or_default();
    assert!(warp_metrics.contains("warp_enabled"), "WARP metrics missing");
}
