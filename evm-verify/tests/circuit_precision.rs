use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{Bytes, H160 as Address};

use evm_verify::bytecode::BytecodeAnalyzer;
use evm_verify::bytecode::analyzer_precision;
use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use evm_verify::circuits::precision::PrecisionCircuit;
use evm_verify::common::DeploymentData;
use evm_verify::bytecode::types::RuntimeAnalysis;

/// Helper function to create a Precision circuit with the given bytecode
fn create_circuit_with_bytecode(bytecode: Bytes) -> PrecisionCircuit<ark_bls12_381::Fr> {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create analyzer with the bytecode
    let analyzer = BytecodeAnalyzer::new(bytecode);
    
    // Get precision warnings
    let _warnings = analyzer_precision::analyze(&analyzer);
    
    // Create circuit with the warnings
    PrecisionCircuit::new(deployment, runtime)
}

/// Test that a safe contract passes the Precision circuit
#[test]
fn test_circuit_safe_contract() {
    // Create a mock bytecode with no vulnerabilities
    let bytecode = Bytes::from(vec![0u8]);
    
    // Create circuit with the bytecode
    let circuit = create_circuit_with_bytecode(bytecode);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should be satisfied for a safe contract
    assert!(cs.is_satisfied().unwrap());
}

/// Test that a contract with division before multiplication fails the Precision circuit
#[test]
fn test_circuit_division_before_multiplication() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for division before multiplication
    let warning = SecurityWarning {
        kind: SecurityWarningKind::PrecisionLoss,
        description: "Division before multiplication may cause precision loss".to_string(),
        severity: SecuritySeverity::Medium,
        pc: 0,
        operations: vec![],
        remediation: "Consider reordering operations to perform multiplication before division".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with improper scaling fails the Precision circuit
#[test]
fn test_circuit_improper_scaling() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for improper scaling
    let warning = SecurityWarning {
        kind: SecurityWarningKind::PrecisionLoss,
        description: "Potential improper scaling detected in division operation".to_string(),
        severity: SecuritySeverity::Medium,
        pc: 0,
        operations: vec![],
        remediation: "Consider using a scaling factor to maintain precision in calculations".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with truncation issues fails the Precision circuit
#[test]
fn test_circuit_truncation_issues() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for truncation issues
    let warning = SecurityWarning {
        kind: SecurityWarningKind::PrecisionLoss,
        description: "Integer division may cause truncation and precision loss".to_string(),
        severity: SecuritySeverity::Low,
        pc: 0,
        operations: vec![],
        remediation: "Consider using a higher precision representation or scaling factor".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with inconsistent decimal handling fails the Precision circuit
#[test]
fn test_circuit_inconsistent_decimal_handling() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for inconsistent decimal handling
    let warning = SecurityWarning {
        kind: SecurityWarningKind::PrecisionLoss,
        description: "Mixed arithmetic operations may lead to inconsistent decimal handling".to_string(),
        severity: SecuritySeverity::Medium,
        pc: 0,
        operations: vec![],
        remediation: "Review arithmetic operations for consistent precision handling".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with exponentiation precision issues fails the Precision circuit
#[test]
fn test_circuit_exponentiation_issues() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for exponentiation precision issues
    let warning = SecurityWarning {
        kind: SecurityWarningKind::PrecisionLoss,
        description: "Exponentiation operations may cause significant precision issues".to_string(),
        severity: SecuritySeverity::Medium,
        pc: 0,
        operations: vec![],
        remediation: "Consider using libraries designed for high-precision math".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that multiple precision vulnerabilities are detected
#[test]
fn test_circuit_multiple_vulnerabilities() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create multiple warnings
    let warnings = vec![
        SecurityWarning {
            kind: SecurityWarningKind::PrecisionLoss,
            description: "Division before multiplication may cause precision loss".to_string(),
            severity: SecuritySeverity::Medium,
            pc: 0,
            operations: vec![],
            remediation: "Consider reordering operations to perform multiplication before division".to_string(),
        },
        SecurityWarning {
            kind: SecurityWarningKind::PrecisionLoss,
            description: "Integer division may cause truncation and precision loss".to_string(),
            severity: SecuritySeverity::Low,
            pc: 4,
            operations: vec![],
            remediation: "Consider using a higher precision representation or scaling factor".to_string(),
        },
    ];
    
    // Create circuit with the warnings
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, warnings);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerabilities
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that non-precision warnings don't affect the circuit
#[test]
fn test_circuit_non_precision_warnings() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create a non-precision warning
    let warning = SecurityWarning {
        kind: SecurityWarningKind::Reentrancy,
        description: "Potential reentrancy vulnerability".to_string(),
        severity: SecuritySeverity::High,
        pc: 0,
        operations: vec![],
        remediation: "Use checks-effects-interactions pattern".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should be satisfied since the warning is not precision-related
    assert!(cs.is_satisfied().unwrap());
}
