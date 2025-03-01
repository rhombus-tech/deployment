use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{H160 as Address, H256, U256};

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::unchecked_calls::UncheckedCallsCircuit;
use evm_verify::common::DeploymentData;
use ark_bn254::Fr;

// Helper function to create a mock deployment
fn create_mock_deployment() -> DeploymentData {
    DeploymentData {
        owner: Address::zero(),
    }
}

// Helper function to create a mock runtime analysis
fn create_mock_runtime() -> RuntimeAnalysis {
    RuntimeAnalysis::default()
}

// Helper function to create an unchecked external call warning
fn create_unchecked_external_call_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UncheckedExternalCall,
        SecuritySeverity::Medium,
        0,
        "Unchecked external call detected".to_string(),
        vec![Operation::ExternalCall {
            target: H256::zero(),
            value: U256::zero(),
            data: vec![],
        }],
        "Always check the return value of external calls to handle potential failures".to_string(),
    )
}

// Helper function to create an unchecked low-level call warning
fn create_unchecked_low_level_call_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UncheckedCallReturn,
        SecuritySeverity::Medium,
        0,
        "Unchecked low-level call detected".to_string(),
        vec![Operation::ExternalCall {
            target: H256::zero(),
            value: U256::zero(),
            data: vec![],
        }],
        "Always check the return value of low-level calls to handle potential failures".to_string(),
    )
}

// Helper function to create an unchecked send/transfer warning
fn create_unchecked_send_transfer_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UncheckedCallReturn,
        SecuritySeverity::Medium,
        0,
        "Unchecked send/transfer detected".to_string(),
        vec![Operation::ValueCall {
            target: H256::zero(),
            value: U256::from(1),
        }],
        "Always check the return value of send/transfer operations to handle potential failures".to_string(),
    )
}

// Helper function to create a missing revert on failure warning
fn create_missing_revert_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UncheckedCallReturn,
        SecuritySeverity::Medium,
        0,
        "Missing revert on call failure detected".to_string(),
        vec![Operation::ExternalCall {
            target: H256::zero(),
            value: U256::zero(),
            data: vec![],
        }],
        "Always revert the transaction if an external call fails to prevent partial execution".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a circuit with no vulnerabilities
    let circuit = UncheckedCallsCircuit::<Fr>::new(
        create_mock_deployment(),
        create_mock_runtime(),
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check if the constraint system is satisfied
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
    assert_eq!(cs.num_witness_variables(), 5);
}

#[test]
fn test_unchecked_external_calls() {
    // Create a circuit with unchecked external call vulnerability
    let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![create_unchecked_external_call_warning()],
        vec![],
        vec![],
        vec![],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check if the constraint system is not satisfied
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
    assert_eq!(cs.num_witness_variables(), 5);
}

#[test]
fn test_unchecked_low_level_calls() {
    // Create a circuit with unchecked low-level call vulnerability
    let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![],
        vec![create_unchecked_low_level_call_warning()],
        vec![],
        vec![],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check if the constraint system is not satisfied
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
    assert_eq!(cs.num_witness_variables(), 5);
}

#[test]
fn test_unchecked_send_transfer() {
    // Create a circuit with unchecked send/transfer vulnerability
    let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![],
        vec![],
        vec![create_unchecked_send_transfer_warning()],
        vec![],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check if the constraint system is not satisfied
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
    assert_eq!(cs.num_witness_variables(), 5);
}

#[test]
fn test_missing_revert() {
    // Create a circuit with missing revert on failure vulnerability
    let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![],
        vec![],
        vec![],
        vec![create_missing_revert_warning()],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check if the constraint system is not satisfied
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
    assert_eq!(cs.num_witness_variables(), 5);
}

#[test]
fn test_multiple_unchecked_call_vulnerabilities() {
    // Create a circuit with multiple unchecked call vulnerabilities
    let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![create_unchecked_external_call_warning()],
        vec![create_unchecked_low_level_call_warning()],
        vec![create_unchecked_send_transfer_warning()],
        vec![create_missing_revert_warning()],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check if the constraint system is not satisfied
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
    assert_eq!(cs.num_witness_variables(), 5);
}
