use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::flash_loan::FlashLoanCircuit;
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

#[test]
fn test_safe_contract() {
    // Create a safe contract with no flash loan vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create circuit with no warnings
    let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_price_oracle_vulnerability() {
    // Create contract with price oracle vulnerability
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for price oracle dependency
    let warning = SecurityWarning::flash_loan_vulnerability(0);
    
    // Create circuit with price oracle vulnerability
    let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_state_manipulation_vulnerability() {
    // Create contract with state manipulation vulnerability
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for state manipulation
    let warning = SecurityWarning::flash_loan_state_manipulation(0);
    
    // Create circuit with state manipulation vulnerability
    let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_missing_slippage_protection() {
    // Create contract with missing slippage protection
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for missing slippage protection
    let warning = SecurityWarning {
        kind: SecurityWarningKind::MissingSlippageProtection,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Missing slippage protection in swap operation".to_string(),
        operations: Vec::new(),
        remediation: "Implement slippage protection with minimum output amount checks".to_string(),
    };
    
    // Create circuit with missing slippage protection
    let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
    let oracle_warning = SecurityWarning::flash_loan_vulnerability(0);
    let state_warning = SecurityWarning::flash_loan_state_manipulation(0);
    let slippage_warning = SecurityWarning {
        kind: SecurityWarningKind::MissingSlippageProtection,
        severity: SecuritySeverity::High,
        pc: 0,
        description: "Missing slippage protection in swap operation".to_string(),
        operations: Vec::new(),
        remediation: "Implement slippage protection with minimum output amount checks".to_string(),
    };
    
    // Create circuit with multiple vulnerabilities
    let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![oracle_warning],
        vec![state_warning],
        vec![slippage_warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}
