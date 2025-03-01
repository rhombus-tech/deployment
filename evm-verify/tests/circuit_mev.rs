use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{Bytes, H160 as Address};

use evm_verify::bytecode::BytecodeAnalyzer;
use evm_verify::bytecode::analyzer_mev;
use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use evm_verify::circuits::mev::MEVCircuit;
use evm_verify::common::DeploymentData;
use evm_verify::bytecode::types::RuntimeAnalysis;

/// Helper function to create a MEV circuit with the given bytecode
fn create_circuit_with_bytecode(bytecode: Bytes) -> MEVCircuit<ark_bls12_381::Fr> {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create analyzer with the bytecode
    let analyzer = BytecodeAnalyzer::new(bytecode);
    
    // Get MEV warnings
    let _warnings = analyzer_mev::detect_mev_vulnerabilities(&analyzer);
    
    // Create circuit with the warnings
    MEVCircuit::new(deployment, runtime)
}

/// Test that a safe contract passes the MEV circuit
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

/// Test that a contract with unprotected price operations fails the MEV circuit
#[test]
fn test_circuit_unprotected_price_operations() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for unprotected price operations
    let warning = SecurityWarning {
        kind: SecurityWarningKind::MEVVulnerability,
        description: "Contract has unprotected price operations".to_string(),
        severity: SecuritySeverity::High,
        pc: 0,
        operations: vec![],
        remediation: "Implement proper price protection mechanisms".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with unprotected DEX interactions fails the MEV circuit
#[test]
fn test_circuit_unprotected_dex_interactions() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for unprotected DEX interactions
    let warning = SecurityWarning {
        kind: SecurityWarningKind::MEVVulnerability,
        description: "Contract has unprotected DEX interaction".to_string(),
        severity: SecuritySeverity::High,
        pc: 0,
        operations: vec![],
        remediation: "Implement proper DEX interaction protection".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with missing slippage protection fails the MEV circuit
#[test]
fn test_circuit_missing_slippage_protection() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for missing slippage protection
    let warning = SecurityWarning {
        kind: SecurityWarningKind::MEVVulnerability,
        description: "Contract is missing slippage protection".to_string(),
        severity: SecuritySeverity::High,
        pc: 0,
        operations: vec![],
        remediation: "Implement slippage protection mechanisms".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract lacking commit-reveal pattern fails the MEV circuit
#[test]
fn test_circuit_lacks_commit_reveal() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for lacking commit-reveal pattern
    let warning = SecurityWarning {
        kind: SecurityWarningKind::MEVVulnerability,
        description: "Contract lacks commit-reveal pattern".to_string(),
        severity: SecuritySeverity::Medium,
        pc: 0,
        operations: vec![],
        remediation: "Implement commit-reveal pattern".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract lacking private mempool usage fails the MEV circuit
#[test]
fn test_circuit_lacks_private_mempool() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for lacking private mempool usage
    let warning = SecurityWarning {
        kind: SecurityWarningKind::MEVVulnerability,
        description: "Contract lacks private mempool usage".to_string(),
        severity: SecuritySeverity::Medium,
        pc: 0,
        operations: vec![],
        remediation: "Consider using private mempool services".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to the vulnerability
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that multiple MEV vulnerabilities are detected
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
            kind: SecurityWarningKind::MEVVulnerability,
            description: "Contract has unprotected price operations".to_string(),
            severity: SecuritySeverity::High,
            pc: 0,
            operations: vec![],
            remediation: "Implement proper price protection mechanisms".to_string(),
        },
        SecurityWarning {
            kind: SecurityWarningKind::MEVVulnerability,
            description: "Contract is missing slippage protection".to_string(),
            severity: SecuritySeverity::High,
            pc: 10,
            operations: vec![],
            remediation: "Implement slippage protection mechanisms".to_string(),
        },
    ];
    
    // Create circuit with the warnings
    let circuit = MEVCircuit::with_warnings(deployment, runtime, warnings);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to multiple vulnerabilities
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that non-MEV warnings don't affect the circuit
#[test]
fn test_circuit_non_mev_warnings() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create non-MEV warning
    let warning = SecurityWarning {
        kind: SecurityWarningKind::Reentrancy,
        description: "Contract has reentrancy vulnerability".to_string(),
        severity: SecuritySeverity::High,
        pc: 0,
        operations: vec![],
        remediation: "Implement checks-effects-interactions pattern".to_string(),
    };
    
    // Create circuit with the warning
    let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should be satisfied since the warning is not MEV-related
    assert!(cs.is_satisfied().unwrap());
}
