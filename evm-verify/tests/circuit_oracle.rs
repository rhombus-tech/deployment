use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_bn254::Fr;
use ethers::types::{H160 as Address};

use evm_verify::circuits::oracle::OracleCircuit;
use evm_verify::common::DeploymentData;
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[test]
fn test_oracle_circuit_with_single_source_dependency() {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Create a warning for single source oracle dependency
    let warning = SecurityWarning {
        kind: SecurityWarningKind::OracleManipulation,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Contract relies on a single oracle source that can be manipulated".to_string(),
        operations: vec![],
        remediation: "Use multiple oracle sources and implement a median or weighted average".to_string(),
    };
    
    // Create deployment data and runtime analysis
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    let runtime = RuntimeAnalysis::default();
    
    // Create circuit with the warning
    let circuit = OracleCircuit::with_warnings(
        deployment,
        runtime,
        vec![warning]
    );
    
    // Generate constraints
    assert!(circuit.generate_constraints(cs.clone()).is_ok());
    
    // Check that constraints are not satisfied (circuit detects the vulnerability)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_oracle_circuit_with_unverified_data() {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Create a warning for unverified oracle data
    let warning = SecurityWarning {
        kind: SecurityWarningKind::OracleManipulation,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Oracle data is used without validation, which could lead to manipulation attacks".to_string(),
        operations: vec![],
        remediation: "Implement data verification mechanisms".to_string(),
    };
    
    // Create deployment data and runtime analysis
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    let runtime = RuntimeAnalysis::default();
    
    // Create circuit with the warning
    let circuit = OracleCircuit::with_warnings(
        deployment,
        runtime,
        vec![warning]
    );
    
    // Generate constraints
    assert!(circuit.generate_constraints(cs.clone()).is_ok());
    
    // Check that constraints are not satisfied (circuit detects the vulnerability)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_oracle_circuit_with_twap_missing() {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Create a warning for missing TWAP mechanisms
    let warning = SecurityWarning {
        kind: SecurityWarningKind::OracleManipulation,
        severity: SecuritySeverity::Medium,
        pc: 0,
        description: "Contract uses price data without Time-Weighted Average Price (TWAP) mechanisms".to_string(),
        operations: vec![],
        remediation: "Implement TWAP mechanisms by storing historical price points".to_string(),
    };
    
    // Create deployment data and runtime analysis
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    let runtime = RuntimeAnalysis::default();
    
    // Create circuit with the warning
    let circuit = OracleCircuit::with_warnings(
        deployment,
        runtime,
        vec![warning]
    );
    
    // Generate constraints
    assert!(circuit.generate_constraints(cs.clone()).is_ok());
    
    // Check that constraints are not satisfied (circuit detects the vulnerability)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_oracle_circuit_safe() {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Create deployment data and runtime analysis
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    let runtime = RuntimeAnalysis::default();
    
    // Create circuit with no warnings
    let circuit = OracleCircuit::with_warnings(
        deployment,
        runtime,
        vec![]
    );
    
    // Generate constraints
    assert!(circuit.generate_constraints(cs.clone()).is_ok());
    
    // Check that constraints are satisfied (no vulnerabilities)
    assert!(cs.is_satisfied().unwrap());
}
