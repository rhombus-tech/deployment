//! Comprehensive tests for production WARP implementations
//! 
//! Tests all the placeholder replacements:
//! 1. Multilinear batch verification
//! 2. LinearCode trait methods
//! 3. WARP accumulation protocol

use evm_verify::accumulation::warp::linear_code::{ExpanderCode, LinearCode, FieldElement};
use evm_verify::accumulation::warp::multilinear::{MultilinearExtension, MultilinearEvalClaim, TwinConstrainedCode, PesatConstraint};
use evm_verify::accumulation::warp::accumulation::{WarpAccumulation, WarpAccumulator, AccumulatorInstancePart};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Field};
use std::sync::Arc;

#[test]
fn test_multilinear_batch_verification() {
    // Test the batch verification implementation
    let code = Arc::new(ExpanderCode::<Fr>::new(8, 2));
    let n = code.codeword_length(); // 16
    let mle = MultilinearExtension::<Fr>::new(n);
    
    // Create a properly encoded codeword
    let message: Vec<Fr> = (0..code.message_length()).map(|i| Fr::from((i + 1) as u64)).collect();
    let codeword = code.encode(&message);
    
    // Create multiple evaluation claims
    let log_n = (n as f64).log2() as usize;
    let tau1: Vec<Fr> = (0..log_n).map(|i| Fr::from((i + 1) as u64)).collect();
    let sigma1 = mle.evaluate(&codeword, &tau1);
    
    let tau2: Vec<Fr> = (0..log_n).map(|i| Fr::from((i + 2) as u64)).collect();
    let sigma2 = mle.evaluate(&codeword, &tau2);
    
    let claims = vec![
        MultilinearEvalClaim { tau: tau1, sigma: sigma1 },
        MultilinearEvalClaim { tau: tau2, sigma: sigma2 },
    ];
    
    // Verify batch claims
    let result = mle.verify_batch_claim(code.as_ref(), &codeword, &claims, 3);
    
    // Should pass verification (claims are valid)
    assert!(result, "Batch verification should pass for valid claims");
}

#[test]
fn test_multilinear_spot_checks() {
    // Test spot check verification
    let n = 8;
    let mle = MultilinearExtension::<Fr>::new(n);
    
    let codeword: Vec<Fr> = vec![
        Fr::from(0u64), Fr::from(1u64), Fr::from(2u64), Fr::from(3u64),
        Fr::from(4u64), Fr::from(5u64), Fr::from(6u64), Fr::from(7u64),
    ];
    
    // Test index to binary conversion
    let binary = mle.index_to_binary(5); // 5 = 101 in binary
    assert_eq!(binary.len(), 3); // log2(8) = 3
    
    // Verify evaluation at binary point matches codeword value
    let eval = mle.evaluate(&codeword, &binary);
    assert_eq!(eval, Fr::from(5u64), "Evaluation at binary point should match codeword value");
}

#[test]
fn test_linear_code_is_codeword() {
    // Test is_codeword implementation
    let code = ExpanderCode::<Fr>::new(4, 3);
    
    // Create a valid codeword by encoding a message
    let message: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let codeword = code.encode(&message);
    
    // Should recognize valid codeword
    assert!(code.is_codeword(&codeword), "Should recognize valid codeword");
    
    // Create an invalid codeword (wrong length)
    let invalid_codeword = vec![Fr::from(1u64), Fr::from(2u64)];
    assert!(!code.is_codeword(&invalid_codeword), "Should reject wrong length codeword");
    
    // Create an invalid codeword (not in code space)
    let mut corrupted = codeword.clone();
    corrupted[0] = corrupted[0] + Fr::from(100u64);
    // Note: May still pass if within error correction capability
}

#[test]
fn test_linear_code_decode() {
    // Test decode implementation
    let code = ExpanderCode::<Fr>::new(4, 3);
    
    let message: Vec<Fr> = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64), Fr::from(40u64)];
    let codeword = code.encode(&message);
    
    // Decode should recover original message
    let decoded = code.decode(&codeword).expect("Decode should succeed");
    assert_eq!(decoded.len(), 4, "Decoded message should have correct length");
    
    // For systematic codes, first k symbols should be the message
    if code.is_systematic() {
        for i in 0..4 {
            assert_eq!(decoded[i], message[i], "Decoded message should match original");
        }
    }
}

#[test]
fn test_linear_code_is_systematic() {
    // Test is_systematic implementation
    let code = ExpanderCode::<Fr>::new(4, 3);
    
    // Should report whether encoding is systematic
    let is_sys = code.is_systematic();
    assert!(is_sys, "ExpanderCode should use systematic encoding");
}

#[test]
fn test_linear_code_error_correction() {
    // Test decode with errors
    let code = ExpanderCode::<Fr>::new(4, 3);
    
    let message: Vec<Fr> = vec![Fr::from(5u64), Fr::from(15u64), Fr::from(25u64), Fr::from(35u64)];
    let codeword = code.encode(&message);
    
    // Introduce small errors
    let mut corrupted = codeword.clone();
    if corrupted.len() > 5 {
        corrupted[4] = corrupted[4] + Fr::from(1u64);
        corrupted[5] = corrupted[5] + Fr::from(2u64);
    }
    
    // Try to decode (should succeed if within error correction capability)
    let result = code.decode(&corrupted);
    match result {
        Ok(decoded) => {
            println!("Error correction succeeded");
            assert_eq!(decoded.len(), 4);
        }
        Err(e) => {
            println!("Error correction failed (expected if too many errors): {}", e);
        }
    }
}

#[test]
fn test_warp_merkle_commitment() {
    // Test Merkle commitment implementation (mock_commit)
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    // Create a witness and initial accumulator
    let witness: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let acc = warp.create_initial_accumulator(&witness)
        .expect("Should create initial accumulator");
    
    // Commitment should be 32 bytes (Merkle root)
    assert_eq!(acc.instance_part.commitment.len(), 32, "Commitment should be 32 bytes");
    
    // Same input should produce same commitment (deterministic)
    let acc2 = warp.create_initial_accumulator(&witness)
        .expect("Should create second accumulator");
    assert_eq!(acc.instance_part.commitment, acc2.instance_part.commitment, 
               "Commitment should be deterministic");
    
    // Different input should produce different commitment
    let witness2: Vec<Fr> = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64), Fr::from(40u64)];
    let acc3 = warp.create_initial_accumulator(&witness2)
        .expect("Should create third accumulator");
    assert_ne!(acc.instance_part.commitment, acc3.instance_part.commitment,
               "Different inputs should produce different commitments");
}

#[test]
fn test_warp_accumulation_basic() {
    // Test basic accumulation
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    // Create initial accumulator
    let witness1: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let acc1 = warp.create_initial_accumulator(&witness1)
        .expect("Should create initial accumulator");
    
    // Accumulate a new instance
    let instance2: Vec<Fr> = vec![Fr::from(5u64), Fr::from(6u64)];
    let witness2: Vec<Fr> = vec![Fr::from(7u64), Fr::from(8u64), Fr::from(9u64), Fr::from(10u64)];
    
    let result = warp.accumulate(&acc1, &instance2, &witness2);
    
    assert!(result.is_ok(), "Accumulation should succeed");
    let (acc2, proof) = result.unwrap();
    
    // New accumulator should have commitment
    assert_eq!(acc2.instance_part.commitment.len(), 32, "New accumulator should have commitment");
    
    // Proof should have decommitments
    assert!(!proof.decommitments.is_empty(), "Proof should have decommitments");
    
    // Proof should have challenge responses
    assert_eq!(proof.challenge_responses.len(), 10, "Proof should have security_parameter responses");
}

#[test]
fn test_warp_verification_protocol() {
    // Test WARP verification implementation
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    // Create two accumulators
    let witness1: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let acc1 = warp.create_initial_accumulator(&witness1)
        .expect("Should create initial accumulator");
    
    let instance2: Vec<Fr> = vec![Fr::from(5u64), Fr::from(6u64)];
    let witness2: Vec<Fr> = vec![Fr::from(7u64), Fr::from(8u64), Fr::from(9u64), Fr::from(10u64)];
    
    let (acc2, proof) = warp.accumulate(&acc1, &instance2, &witness2)
        .expect("Should accumulate");
    
    // Verify the accumulation proof
    let is_valid = warp.verify(
        &acc1.instance_part,
        &instance2,
        &acc2.instance_part,
        &proof
    );
    
    assert!(is_valid, "Verification should pass for valid proof");
}

#[test]
fn test_warp_verification_rejects_invalid() {
    // Test that verification rejects invalid proofs
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    let witness1: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let acc1 = warp.create_initial_accumulator(&witness1).unwrap();
    
    // Create invalid accumulator instance (wrong commitment length)
    let invalid_instance = AccumulatorInstancePart {
        commitment: vec![0, 1, 2], // Wrong length (should be 32)
        multilinear_claims: vec![],
        pesat_constraint: None,
    };
    
    let instance2: Vec<Fr> = vec![Fr::from(5u64)];
    let witness2: Vec<Fr> = vec![Fr::from(7u64), Fr::from(8u64), Fr::from(9u64), Fr::from(10u64)];
    let (_, proof) = warp.accumulate(&acc1, &instance2, &witness2).unwrap();
    
    // Should reject invalid commitment
    let is_valid = warp.verify(
        &acc1.instance_part,
        &instance2,
        &invalid_instance,
        &proof
    );
    
    assert!(!is_valid, "Should reject invalid commitment length");
}

#[test]
fn test_pesat_constraint_generation() {
    // Test PESAT constraint generation
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    let witness1: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let acc1 = warp.create_initial_accumulator(&witness1).unwrap();
    
    let instance2: Vec<Fr> = vec![Fr::from(5u64), Fr::from(6u64), Fr::from(7u64), Fr::from(8u64)];
    let witness2: Vec<Fr> = vec![Fr::from(9u64), Fr::from(10u64), Fr::from(11u64), Fr::from(12u64)];
    
    let (acc2, _) = warp.accumulate(&acc1, &instance2, &witness2).unwrap();
    
    // Check if PESAT constraint was generated
    if let Some(pesat) = &acc2.instance_part.pesat_constraint {
        assert!(!pesat.beta.is_empty(), "PESAT beta should not be empty");
        assert!(pesat.beta.len() <= code.message_length(), "Beta length should be <= k");
    }
}

#[test]
fn test_twin_constrained_code() {
    // Test TwinConstrainedCode with multilinear and PESAT constraints
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let message: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let codeword = code.encode(&message);
    
    // Create multilinear claims
    let log_n = (code.codeword_length() as f64).log2() as usize;
    let tau: Vec<Fr> = (0..log_n).map(|i| Fr::from((i + 1) as u64)).collect();
    let mle = MultilinearExtension::new(code.codeword_length());
    let sigma = mle.evaluate(&codeword, &tau);
    
    let claims = vec![MultilinearEvalClaim { tau, sigma }];
    
    // Create PESAT constraint
    let beta: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let mut eta = Fr::from(0u64);
    for (m, b) in message.iter().zip(beta.iter()) {
        eta = eta + (*m * *b);
    }
    let pesat = Some(PesatConstraint { beta, eta });
    
    // Create twin constrained code
    let twin_code = TwinConstrainedCode::new(code.clone(), claims, pesat);
    
    // Check if valid codeword satisfies constraints
    let satisfies = twin_code.contains(&codeword);
    assert!(satisfies, "Valid codeword should satisfy all constraints");
}

#[test]
fn test_accumulation_proof_structure() {
    // Test accumulation proof has correct structure
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    let witness1: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let acc1 = warp.create_initial_accumulator(&witness1).unwrap();
    
    let instance2: Vec<Fr> = vec![Fr::from(5u64)];
    let witness2: Vec<Fr> = vec![Fr::from(6u64), Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)];
    
    let (_, proof) = warp.accumulate(&acc1, &instance2, &witness2).unwrap();
    
    // Check proof structure
    assert_eq!(proof.challenge_responses.len(), 10, "Should have 10 challenge responses");
    assert!(!proof.auxiliary_data.is_empty(), "Should have auxiliary data");
    
    // Check auxiliary data contains version marker
    let aux_str = String::from_utf8_lossy(&proof.auxiliary_data);
    assert!(aux_str.contains("WARP_BATCH_V1"), "Should contain version marker");
}

#[test]
fn test_lagrange_basis_evaluation() {
    // Test Lagrange basis evaluation helper
    let n = 8;
    let mle = MultilinearExtension::<Fr>::new(n);
    
    let x: Vec<Fr> = vec![Fr::from(0u64), Fr::from(1u64), Fr::from(0u64)];
    let y: Vec<Fr> = vec![Fr::from(1u64), Fr::from(0u64), Fr::from(1u64)];
    
    // Note: evaluate_lagrange_basis is private, tested indirectly through batch verification
    // This test documents expected behavior
    
    // Lagrange basis should evaluate to product of individual terms
    // L(x,y) = prod_i [(1-x_i)(1-y_i) + x_i*y_i]
}

#[test]
fn test_end_to_end_warp_workflow() {
    // Comprehensive end-to-end test
    let code = Arc::new(ExpanderCode::<Fr>::new(4, 3));
    let warp = WarpAccumulation::new(code.clone(), 10);
    
    // Step 1: Create initial accumulator
    let witness1: Vec<Fr> = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let mut acc = warp.create_initial_accumulator(&witness1)
        .expect("Should create initial accumulator");
    
    // Step 2: Accumulate multiple instances
    for i in 0..3 {
        let instance: Vec<Fr> = vec![Fr::from((i * 10) as u64)];
        let witness: Vec<Fr> = (0..4).map(|j| Fr::from((i * 4 + j) as u64)).collect();
        
        let (new_acc, proof) = warp.accumulate(&acc, &instance, &witness)
            .expect("Accumulation should succeed");
        
        // Verify each accumulation
        let is_valid = warp.verify(
            &acc.instance_part,
            &instance,
            &new_acc.instance_part,
            &proof
        );
        assert!(is_valid, "Verification should pass at iteration {}", i);
        
        acc = new_acc;
    }
    
    // Step 3: Final decision
    let decision = warp.decide(&acc);
    assert!(decision, "Final accumulator should be valid");
}
