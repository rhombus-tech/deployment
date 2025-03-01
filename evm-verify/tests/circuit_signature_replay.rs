use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::signature_replay::SignatureReplayCircuit;
use evm_verify::common::DeploymentData;

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

// Helper function to create a missing nonce warning
fn create_missing_nonce_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::SignatureReplay,
        SecuritySeverity::High,
        0,
        "Potential signature replay vulnerability: missing nonce protection".to_string(),
        vec![Operation::Cryptography {
            op_type: "signature_verification".to_string(),
            input: None,
        }],
        "Implement nonce-based protection to prevent signature replay attacks".to_string(),
    )
}

// Helper function to create a missing expiration warning
fn create_missing_expiration_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::SignatureReplay,
        SecuritySeverity::Medium,
        0,
        "Potential signature replay vulnerability: missing expiration timestamp".to_string(),
        vec![Operation::Cryptography {
            op_type: "signature_verification".to_string(),
            input: None,
        }],
        "Implement timestamp-based expiration to prevent signature replay attacks".to_string(),
    )
}

// Helper function to create an ECRECOVER misuse warning
fn create_ecrecover_misuse_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::SignatureReplay,
        SecuritySeverity::High,
        0,
        "Potential ECRECOVER misuse that may lead to signature replay".to_string(),
        vec![Operation::Cryptography {
            op_type: "ecrecover".to_string(),
            input: None,
        }],
        "Ensure proper validation of signatures to prevent replay attacks".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a safe contract with no signature replay vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create circuit with no warnings
    let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 8);
    
    // Check the number of input variables
    assert_eq!(cs.num_instance_variables(), 1);
    
    // Check the number of witness variables
    assert_eq!(cs.num_witness_variables(), 4);
}

#[test]
fn test_missing_nonce_protection() {
    // Create contract with missing nonce protection
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for missing nonce protection
    let warning = create_missing_nonce_warning();
    
    // Create circuit with missing nonce protection
    let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_missing_expiration_timestamp() {
    // Create contract with missing expiration timestamp
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for missing expiration timestamp
    let warning = create_missing_expiration_warning();
    
    // Create circuit with missing expiration timestamp
    let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![warning],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_ecrecover_misuse() {
    // Create contract with ECRECOVER misuse
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for ECRECOVER misuse
    let warning = create_ecrecover_misuse_warning();
    
    // Create circuit with ECRECOVER misuse
    let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
        vec![warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_multiple_vulnerabilities() {
    // Create contract with multiple vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warnings for multiple vulnerabilities
    let nonce_warning = create_missing_nonce_warning();
    let expiration_warning = create_missing_expiration_warning();
    let ecrecover_warning = create_ecrecover_misuse_warning();
    
    // Create circuit with multiple vulnerabilities
    let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![nonce_warning],
        vec![expiration_warning],
        vec![ecrecover_warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}
