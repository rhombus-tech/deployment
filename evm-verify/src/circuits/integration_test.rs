// ZODA Complete EVM Circuit Integration Test
// Tests full zkEVM proof generation pipeline for EF compliance

use super::*;
use crate::circuits::complete_evm_circuit::*;
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use ark_bn254::Fr;
use ethers::types::{Transaction, Block, H256, U256, Address};
use std::str::FromStr;

#[tokio::test]
async fn test_complete_evm_circuit_transaction_proving() {
    println!("🚀 Testing Complete EVM Circuit - Full Transaction Proving");
    
    // Create test transaction
    let test_tx = create_test_transaction();
    let test_block = create_test_block();
    
    // Initialize complete EVM circuit
    let mut circuit = create_test_complete_evm_circuit();
    
    // Generate complete proof
    let start_time = std::time::Instant::now();
    let proof_result = circuit.prove_transaction(&test_tx, &test_block).await;
    let proving_time = start_time.elapsed();
    
    assert!(proof_result.is_ok(), "Complete EVM proof generation failed");
    let proof = proof_result.unwrap();
    
    // Validate proof structure
    assert!(proof.is_valid, "Generated proof should be valid");
    assert!(!proof.combined_proof_hash.is_zero(), "Combined proof hash should not be zero");
    assert!(!proof.verification_key.is_empty(), "Verification key should not be empty");
    
    // Check EF compliance
    assert!(proof.ef_compliance.realtime_capable, "Should meet realtime requirements");
    assert!(proof.ef_compliance.hardware_compliant, "Should meet hardware requirements");
    assert_eq!(proof.ef_compliance.security_level_bits, 128, "Should provide 128-bit security");
    assert!(proof.ef_compliance.proof_size_bytes < 300 * 1024, "Proof size should be <300KiB");
    assert_eq!(proof.ef_compliance.opcode_coverage_percent, 100.0, "Should have complete opcode coverage");
    assert!(proof.ef_compliance.stack_memory_complete, "Stack/memory verification should be complete");
    assert!(proof.ef_compliance.gas_metering_accurate, "Gas metering should be accurate");
    assert!(proof.ef_compliance.exception_handling_complete, "Exception handling should be complete");
    assert_eq!(proof.ef_compliance.compliance_score, 100.0, "Should achieve perfect compliance score");
    
    // Verify proof
    let verification_result = circuit.verify_complete_proof(&proof).await;
    assert!(verification_result.is_ok(), "Proof verification should succeed");
    assert!(verification_result.unwrap(), "Proof should be valid");
    
    // Check performance metrics
    assert!(proving_time.as_millis() < 10_000, "Proving should take <10s for EF compliance");
    assert!(proof.performance.total_time_ms < 10_000, "Total time should be <10s");
    assert!(proof.performance.throughput_steps_per_sec > 0.0, "Should have positive throughput");
    assert!(proof.performance.compression_ratio > 1.0, "Should achieve compression");
    
    println!("✅ Complete EVM Circuit Test Passed!");
    println!("   Proving Time: {}ms", proving_time.as_millis());
    println!("   Proof Size: {} bytes", proof.ef_compliance.proof_size_bytes);
    println!("   Security Level: {} bits", proof.ef_compliance.security_level_bits);
    println!("   Compliance Score: {:.1}%", proof.ef_compliance.compliance_score);
    println!("   Throughput: {:.0} steps/sec", proof.performance.throughput_steps_per_sec);
}

#[tokio::test] 
async fn test_ef_compliance_requirements() {
    println!("🎯 Testing Ethereum Foundation Compliance Requirements");
    
    let mut circuit = create_test_complete_evm_circuit();
    let test_tx = create_test_transaction();
    let test_block = create_test_block();
    
    // Test multiple transactions to validate consistency
    let mut proofs = Vec::new();
    let mut total_proving_time = 0u128;
    
    for i in 0..5 {
        let mut tx = test_tx.clone();
        tx.nonce = U256::from(i);
        
        let start = std::time::Instant::now();
        let proof = circuit.prove_transaction(&tx, &test_block).await.unwrap();
        total_proving_time += start.elapsed().as_millis();
        
        proofs.push(proof);
    }
    
    let avg_proving_time = total_proving_time / proofs.len() as u128;
    
    // Validate EF requirements across all proofs
    for (i, proof) in proofs.iter().enumerate() {
        // Requirement 1: Realtime proving (≤10s for P99 blocks)
        assert!(proof.performance.total_time_ms < 10_000, 
                "Proof {} failed realtime requirement: {}ms", i, proof.performance.total_time_ms);
        
        // Requirement 2: Security (≥128 bits)
        assert!(proof.ef_compliance.security_level_bits >= 128,
                "Proof {} failed security requirement: {} bits", i, proof.ef_compliance.security_level_bits);
        
        // Requirement 3: Proof size (≤300KiB)
        assert!(proof.ef_compliance.proof_size_bytes <= 300 * 1024,
                "Proof {} failed size requirement: {} bytes", i, proof.ef_compliance.proof_size_bytes);
        
        // Requirement 4: Hardware compliance (consumer hardware)
        assert!(proof.ef_compliance.hardware_compliant,
                "Proof {} failed hardware compliance", i);
        
        // Requirement 5: Complete EVM coverage
        assert_eq!(proof.ef_compliance.opcode_coverage_percent, 100.0,
                   "Proof {} incomplete opcode coverage: {}%", i, proof.ef_compliance.opcode_coverage_percent);
    }
    
    println!("✅ EF Compliance Test Passed!");
    println!("   Average Proving Time: {}ms (requirement: <10,000ms)", avg_proving_time);
    println!("   Security Level: {} bits (requirement: ≥128 bits)", proofs[0].ef_compliance.security_level_bits);
    println!("   Max Proof Size: {} bytes (requirement: ≤307,200 bytes)", 
             proofs.iter().map(|p| p.ef_compliance.proof_size_bytes).max().unwrap());
    println!("   Opcode Coverage: {}% (requirement: 100%)", proofs[0].ef_compliance.opcode_coverage_percent);
}

#[tokio::test]
async fn test_circuit_component_integration() {
    println!("🔧 Testing Circuit Component Integration");
    
    let mut circuit = create_test_complete_evm_circuit();
    let test_tx = create_test_transaction();
    let test_block = create_test_block();
    
    // Generate proof and examine components
    let proof = circuit.prove_transaction(&test_tx, &test_block).await.unwrap();
    
    // Test execution trace component
    assert!(!proof.execution_proof.execution_steps.is_empty(), "Should have execution steps");
    assert!(proof.execution_proof.performance.total_steps > 0, "Should have processed steps");
    assert!(!proof.execution_proof.compressed_trace.is_empty(), "Should have compressed trace");
    
    // Test stack/memory component
    assert!(proof.stack_memory_proof.stack_valid, "Stack verification should be valid");
    assert!(proof.stack_memory_proof.memory_valid, "Memory verification should be valid");
    assert!(!proof.stack_memory_proof.proof_data.is_empty(), "Should have stack/memory proof data");
    
    // Test opcode validation component
    assert!(proof.opcode_proof.is_valid, "Opcode validation should be valid");
    assert!(proof.opcode_proof.total_executions > 0, "Should have opcode executions");
    assert!(proof.opcode_proof.violations.is_empty(), "Should have no opcode violations");
    
    // Test component integration consistency
    let execution_steps = proof.execution_proof.execution_steps.len();
    let opcode_executions = proof.opcode_proof.total_executions;
    assert_eq!(execution_steps, opcode_executions, 
               "Execution steps ({}) should match opcode executions ({})", 
               execution_steps, opcode_executions);
    
    println!("✅ Circuit Component Integration Test Passed!");
    println!("   Execution Steps: {}", execution_steps);
    println!("   Stack Operations: {}", proof.stack_memory_proof.stack_operations.len());
    println!("   Memory Operations: {}", proof.stack_memory_proof.memory_operations.len());
    println!("   Opcode Violations: {}", proof.opcode_proof.violations.len());
}

#[tokio::test]
async fn test_performance_benchmarks() {
    println!("📊 Testing Performance Benchmarks");
    
    let mut circuit = create_test_complete_evm_circuit();
    
    // Test different transaction complexities
    let simple_tx = create_simple_transaction();
    let complex_tx = create_complex_transaction();
    
    let test_block = create_test_block();
    
    // Benchmark simple transaction
    let start = std::time::Instant::now();
    let simple_proof = circuit.prove_transaction(&simple_tx, &test_block).await.unwrap();
    let simple_time = start.elapsed().as_millis();
    
    // Benchmark complex transaction
    let start = std::time::Instant::now();
    let complex_proof = circuit.prove_transaction(&complex_tx, &test_block).await.unwrap();
    let complex_time = start.elapsed().as_millis();
    
    // Validate performance scaling
    assert!(simple_time < complex_time, "Simple tx should be faster than complex tx");
    assert!(simple_time < 5_000, "Simple tx should prove in <5s");
    assert!(complex_time < 10_000, "Complex tx should prove in <10s");
    
    // Check proof size scaling
    assert!(simple_proof.ef_compliance.proof_size_bytes < complex_proof.ef_compliance.proof_size_bytes,
            "Simple tx should have smaller proof than complex tx");
    
    // Validate throughput
    let simple_throughput = simple_proof.performance.throughput_steps_per_sec;
    let complex_throughput = complex_proof.performance.throughput_steps_per_sec;
    
    assert!(simple_throughput > 1000.0, "Should achieve >1000 steps/sec for simple tx");
    assert!(complex_throughput > 500.0, "Should achieve >500 steps/sec for complex tx");
    
    println!("✅ Performance Benchmark Test Passed!");
    println!("   Simple Transaction: {}ms, {} bytes, {:.0} steps/sec", 
             simple_time, simple_proof.ef_compliance.proof_size_bytes, simple_throughput);
    println!("   Complex Transaction: {}ms, {} bytes, {:.0} steps/sec",
             complex_time, complex_proof.ef_compliance.proof_size_bytes, complex_throughput);
}

#[tokio::test]
async fn test_proof_verification() {
    println!("🔍 Testing Proof Verification");
    
    let mut circuit = create_test_complete_evm_circuit();
    let test_tx = create_test_transaction();
    let test_block = create_test_block();
    
    // Generate valid proof
    let valid_proof = circuit.prove_transaction(&test_tx, &test_block).await.unwrap();
    
    // Test valid proof verification
    let verification_result = circuit.verify_complete_proof(&valid_proof).await.unwrap();
    assert!(verification_result, "Valid proof should verify successfully");
    
    // Test proof tampering detection
    let mut tampered_proof = valid_proof.clone();
    tampered_proof.combined_proof_hash = H256::random();
    
    let tampered_verification = circuit.verify_complete_proof(&tampered_proof).await.unwrap();
    assert!(!tampered_verification, "Tampered proof should fail verification");
    
    println!("✅ Proof Verification Test Passed!");
}

// Helper functions

fn create_test_complete_evm_circuit() -> CompleteEVMCircuit<Fr> {
    let deployment = DeploymentData::default();
    let runtime = RuntimeAnalysis::default();
    
    let execution_trace = EVMExecutionTrace::new();
    let stack_memory_verifier = StackMemoryVerifier::new();
    let opcode_validator = OpcodeValidationCircuit::new();
    let state_circuit = crate::circuits::evm_state::EVMStateCircuit::new(deployment.clone(), runtime.clone());
    
    CompleteEVMCircuit::new(
        execution_trace,
        stack_memory_verifier,
        opcode_validator,
        state_circuit,
        deployment,
        runtime,
    )
}

fn create_test_transaction() -> Transaction {
    Transaction {
        hash: H256::from_str("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap(),
        nonce: U256::from(1),
        block_hash: Some(H256::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef").unwrap()),
        block_number: Some(U256::from(1000000)),
        transaction_index: Some(U256::from(0)),
        from: Address::from_str("0x742d35cc6ba4c58c12c8deaa8ba3e717537e9123").unwrap(),
        to: Some(Address::from_str("0x8ba1f109551bd432803012645hac136c22c551bd").unwrap()),
        value: U256::from(1000000000000000000u64), // 1 ETH
        gas_price: Some(U256::from(20000000000u64)), // 20 gwei
        gas: U256::from(21000),
        input: vec![0x60, 0x80, 0x60, 0x40, 0x52], // Simple contract deployment bytecode
        v: U256::from(27),
        r: U256::from_str("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap(),
        s: U256::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef").unwrap(),
        transaction_type: Some(U256::from(0)),
        access_list: None,
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        chain_id: Some(U256::from(1)),
        other: Default::default(),
    }
}

fn create_simple_transaction() -> Transaction {
    let mut tx = create_test_transaction();
    tx.input = vec![]; // Empty input for simple transfer
    tx.gas = U256::from(21000); // Minimal gas
    tx
}

fn create_complex_transaction() -> Transaction {
    let mut tx = create_test_transaction();
    // Complex contract interaction bytecode
    tx.input = vec![
        0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57, 0x60, 0x00, 0x80, 0xfd,
        0x5b, 0x50, 0x60, 0x40, 0x51, 0x80, 0x82, 0x52, 0x60, 0x20, 0x82, 0x01, 0x91, 0x50, 0x50, 0x60,
        0x40, 0x51, 0x80, 0x91, 0x03, 0x90, 0xf3, // More complex bytecode
    ];
    tx.gas = U256::from(100000); // Higher gas limit
    tx
}

fn create_test_block() -> Block<H256> {
    Block {
        hash: Some(H256::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef").unwrap()),
        parent_hash: H256::from_str("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap(),
        uncles_hash: H256::zero(),
        author: Some(Address::from_str("0x0000000000000000000000000000000000000000").unwrap()),
        state_root: H256::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef").unwrap(),
        transactions_root: H256::zero(),
        receipts_root: H256::zero(),
        number: Some(U256::from(1000000)),
        gas_used: U256::from(21000),
        gas_limit: U256::from(8000000),
        extra_data: Default::default(),
        logs_bloom: None,
        timestamp: U256::from(1640995200), // 2022-01-01
        difficulty: U256::from(1000000),
        total_difficulty: Some(U256::from(10000000)),
        seal_fields: vec![],
        uncles: vec![],
        transactions: vec![],
        size: Some(U256::from(1000)),
        mix_hash: Some(H256::zero()),
        nonce: Some(H256::zero()),
        base_fee_per_gas: Some(U256::from(1000000000)),
        withdrawals_root: None,
        withdrawals: None,
        other: Default::default(),
    }
}
