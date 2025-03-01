use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::common::DeploymentData;
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use evm_verify::circuits::IntegerOverflowCircuit;

#[test]
fn test_safe_contract_satisfies_circuit() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create circuit with no warnings
    let circuit = IntegerOverflowCircuit::<Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 12);
}

#[test]
fn test_overflow_addition_vulnerable_contract() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for integer overflow in addition
    let warning = SecurityWarning {
        kind: SecurityWarningKind::IntegerOverflow,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Potential integer overflow in addition operation".to_string(),
        operations: vec![],
        remediation: "Use SafeMath or checked arithmetic".to_string(),
    };
    
    // Create circuit with warning
    let circuit = IntegerOverflowCircuit::<Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_overflow_multiplication_vulnerable_contract() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for integer overflow in multiplication
    let warning = SecurityWarning {
        kind: SecurityWarningKind::IntegerOverflow,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Potential integer overflow in multiplication operation".to_string(),
        operations: vec![],
        remediation: "Use SafeMath or checked arithmetic".to_string(),
    };
    
    // Create circuit with warning
    let circuit = IntegerOverflowCircuit::<Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_underflow_subtraction_vulnerable_contract() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for integer underflow in subtraction
    let warning = SecurityWarning {
        kind: SecurityWarningKind::IntegerUnderflow,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Potential integer underflow in subtraction operation".to_string(),
        operations: vec![],
        remediation: "Use SafeMath or checked arithmetic".to_string(),
    };
    
    // Create circuit with warning
    let circuit = IntegerOverflowCircuit::<Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_underflow_decrement_vulnerable_contract() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for integer underflow in decrement
    let warning = SecurityWarning {
        kind: SecurityWarningKind::IntegerUnderflow,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Potential integer underflow in decrement operation".to_string(),
        operations: vec![],
        remediation: "Use SafeMath or checked arithmetic".to_string(),
    };
    
    // Create circuit with warning
    let circuit = IntegerOverflowCircuit::<Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_multiple_vulnerabilities() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warnings for both overflow and underflow
    let overflow_warning = SecurityWarning {
        kind: SecurityWarningKind::IntegerOverflow,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Potential integer overflow in addition operation".to_string(),
        operations: vec![],
        remediation: "Use SafeMath or checked arithmetic".to_string(),
    };
    
    let underflow_warning = SecurityWarning {
        kind: SecurityWarningKind::IntegerUnderflow,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Potential integer underflow in subtraction operation".to_string(),
        operations: vec![],
        remediation: "Use SafeMath or checked arithmetic".to_string(),
    };
    
    // Create circuit with both warnings
    let circuit = IntegerOverflowCircuit::<Fr>::with_warnings(
        deployment,
        runtime,
        vec![overflow_warning],
        vec![underflow_warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}
