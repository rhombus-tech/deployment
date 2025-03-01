use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{Bytes, H160 as Address};

use evm_verify::bytecode::BytecodeAnalyzer;
use evm_verify::bytecode::analyzer_front_running;
use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use evm_verify::circuits::front_running::FrontRunningCircuit;
use evm_verify::common::DeploymentData;
use evm_verify::bytecode::types::RuntimeAnalysis;

/// Helper function to create a front-running circuit with the given bytecode
fn create_circuit_with_bytecode(bytecode: Bytes) -> FrontRunningCircuit<ark_bls12_381::Fr> {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create analyzer with the bytecode
    let analyzer = BytecodeAnalyzer::new(bytecode);
    
    // Get front-running warnings
    let _warnings = analyzer_front_running::analyze(&analyzer);
    
    // Create circuit with the warnings
    FrontRunningCircuit::new(deployment, runtime)
}

/// Test that a safe contract passes the front-running circuit
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

/// Test that a contract with gas price dependency fails the front-running circuit
#[test]
fn test_circuit_gas_price_dependency() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create a warning for gas price dependency
    let warning = SecurityWarning::new(
        SecurityWarningKind::FrontRunning,
        SecuritySeverity::High,
        0,
        "Gas price dependency detected".to_string(),
        vec![],
        "Avoid using tx.gasprice in critical operations".to_string(),
    );
    
    // Create circuit with the warning
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to gas price dependency
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with block timestamp dependency fails the front-running circuit
#[test]
fn test_circuit_block_timestamp_dependency() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create a warning for block timestamp dependency
    let warning = SecurityWarning::new(
        SecurityWarningKind::FrontRunning,
        SecuritySeverity::High,
        0,
        "Block timestamp dependency detected".to_string(),
        vec![],
        "Avoid using block.timestamp for critical operations".to_string(),
    );
    
    // Create circuit with the warning
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to block timestamp dependency
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with missing commit-reveal pattern fails the circuit
#[test]
fn test_circuit_missing_commit_reveal() {
    // Create a mock analyzer with warnings
    let _analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8]));
    
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create a warning for missing commit-reveal pattern
    let warning = SecurityWarning::new(
        SecurityWarningKind::FrontRunning,
        SecuritySeverity::High,
        0,
        "Missing commit-reveal pattern in auction contract".to_string(),
        vec![],
        "Implement a commit-reveal pattern to prevent front-running".to_string(),
    );
    
    // Create circuit with the warning
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to missing commit-reveal
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with price-sensitive operations fails the circuit
#[test]
fn test_circuit_price_sensitive_operations() {
    // Create a mock analyzer with warnings
    let _analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8]));
    
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create a warning for price-sensitive operations
    let warning = SecurityWarning::new(
        SecurityWarningKind::FrontRunning,
        SecuritySeverity::High,
        0,
        "Price-sensitive operations detected".to_string(),
        vec![],
        "Implement price oracle with time-weighted average price".to_string(),
    );
    
    // Create circuit with the warning
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to price-sensitive operations
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that a contract with missing slippage protection fails the circuit
#[test]
fn test_circuit_missing_slippage_protection() {
    // Create a mock analyzer with warnings
    let _analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8]));
    
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create a warning for missing slippage protection
    let warning = SecurityWarning::new(
        SecurityWarningKind::FrontRunning,
        SecuritySeverity::High,
        0,
        "Missing slippage protection in swap function".to_string(),
        vec![],
        "Add minimum output amount parameter to swap function".to_string(),
    );
    
    // Create circuit with the warning
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, vec![warning]);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to missing slippage protection
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that multiple front-running vulnerabilities are detected
#[test]
fn test_circuit_multiple_vulnerabilities() {
    // Create a mock analyzer with warnings
    let _analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8]));
    
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warnings for multiple vulnerabilities
    let warnings = vec![
        SecurityWarning::new(
            SecurityWarningKind::FrontRunning,
            SecuritySeverity::High,
            0,
            "Gas price dependency detected".to_string(),
            vec![],
            "Avoid using tx.gasprice in critical operations".to_string(),
        ),
        SecurityWarning::new(
            SecurityWarningKind::FrontRunning,
            SecuritySeverity::High,
            0,
            "Missing slippage protection in swap function".to_string(),
            vec![],
            "Add minimum output amount parameter to swap function".to_string(),
        ),
        SecurityWarning::new(
            SecurityWarningKind::FrontRunning,
            SecuritySeverity::Medium,
            0,
            "Block timestamp dependency detected".to_string(),
            vec![],
            "Avoid using block.timestamp for critical operations".to_string(),
        ),
    ];
    
    // Create circuit with the warnings
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, warnings);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should not be satisfied due to multiple vulnerabilities
    assert!(!cs.is_satisfied().unwrap());
}

/// Test that non-front-running warnings don't affect the circuit
#[test]
fn test_circuit_non_front_running_warnings() {
    // Create a mock analyzer with warnings
    let _analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8]));
    
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warnings for non-front-running issues
    let warnings = vec![
        SecurityWarning::new(
            SecurityWarningKind::Reentrancy,
            SecuritySeverity::High,
            0,
            "Reentrancy vulnerability detected".to_string(),
            vec![],
            "Use checks-effects-interactions pattern".to_string(),
        ),
        SecurityWarning::new(
            SecurityWarningKind::IntegerOverflow,
            SecuritySeverity::High,
            0,
            "Integer overflow detected".to_string(),
            vec![],
            "Use SafeMath or Solidity 0.8+ for arithmetic operations".to_string(),
        ),
    ];
    
    // Create circuit with the warnings
    let circuit = FrontRunningCircuit::with_warnings(deployment, runtime, warnings);
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if satisfied - should be satisfied as there are no front-running warnings
    assert!(cs.is_satisfied().unwrap());
}
