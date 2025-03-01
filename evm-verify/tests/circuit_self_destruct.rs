use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{H160 as Address, H256, U256};

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::self_destruct::SelfDestructCircuit;
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

// Helper function to create an unprotected self-destruct warning
fn create_unprotected_self_destruct_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UnprotectedSelfDestruct,
        SecuritySeverity::Critical,
        0,
        "Unprotected self-destruct detected".to_string(),
        vec![Operation::SelfDestruct {
            beneficiary: H256::zero(),
        }],
        "Add proper access control to self-destruct operations".to_string(),
    )
}

// Helper function to create a delegatecall to self-destruct warning
fn create_delegatecall_self_destruct_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::DelegateCallMisuse,
        SecuritySeverity::Critical,
        0,
        "Delegatecall to contract with self-destruct detected".to_string(),
        vec![Operation::DelegateCall {
            target: H256::zero(),
            data: vec![],
        }],
        "Verify delegatecall targets do not contain self-destruct operations".to_string(),
    )
}

// Helper function to create a self-destruct in constructor warning
fn create_self_destruct_in_constructor_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UnprotectedSelfDestruct,
        SecuritySeverity::Critical,
        0,
        "Self-destruct in constructor detected".to_string(),
        vec![Operation::SelfDestruct {
            beneficiary: H256::zero(),
        }],
        "Remove self-destruct from constructor".to_string(),
    )
}

// Helper function to create a conditional self-destruct warning
fn create_conditional_self_destruct_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UnprotectedSelfDestruct,
        SecuritySeverity::High,
        0,
        "Conditional self-destruct with weak conditions detected".to_string(),
        vec![
            Operation::Comparison {
                op_type: "weak_condition".to_string(),
            },
            Operation::SelfDestruct {
                beneficiary: H256::zero(),
            },
        ],
        "Strengthen conditions for self-destruct operations".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a circuit with no vulnerabilities
    let circuit = SelfDestructCircuit::<Fr>::new(
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
fn test_unprotected_self_destruct() {
    // Create a circuit with unprotected self-destruct vulnerability
    let circuit = SelfDestructCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![create_unprotected_self_destruct_warning()],
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
fn test_delegatecall_self_destruct() {
    // Create a circuit with delegatecall to self-destruct vulnerability
    let circuit = SelfDestructCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![],
        vec![create_delegatecall_self_destruct_warning()],
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
fn test_self_destruct_in_constructor() {
    // Create a circuit with self-destruct in constructor vulnerability
    let circuit = SelfDestructCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![],
        vec![],
        vec![create_self_destruct_in_constructor_warning()],
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
fn test_conditional_self_destruct() {
    // Create a circuit with conditional self-destruct vulnerability
    let circuit = SelfDestructCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![],
        vec![],
        vec![],
        vec![create_conditional_self_destruct_warning()],
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
fn test_multiple_self_destruct_vulnerabilities() {
    // Create a circuit with multiple self-destruct vulnerabilities
    let circuit = SelfDestructCircuit::<Fr>::with_warnings(
        create_mock_deployment(),
        create_mock_runtime(),
        vec![create_unprotected_self_destruct_warning()],
        vec![create_delegatecall_self_destruct_warning()],
        vec![create_self_destruct_in_constructor_warning()],
        vec![create_conditional_self_destruct_warning()],
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
