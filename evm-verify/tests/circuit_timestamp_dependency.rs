use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::timestamp_dependency::TimestampDependencyCircuit;
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

// Helper function to create a block timestamp dependency warning
fn create_block_timestamp_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::BlockTimestampDependency,
        SecuritySeverity::Medium,
        0,
        "Block timestamp dependency detected".to_string(),
        vec![Operation::Timestamp],
        "Avoid using block.timestamp for critical contract logic".to_string(),
    )
}

// Helper function to create an unsafe timestamp comparison warning
fn create_unsafe_comparison_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UnsafeTimestampComparison,
        SecuritySeverity::Medium,
        0,
        "Unsafe timestamp comparison detected".to_string(),
        vec![Operation::Comparison {
            op_type: "timestamp_equality".to_string(),
        }],
        "Use safe comparison methods for timestamps".to_string(),
    )
}

// Helper function to create a time-based randomness warning
fn create_time_randomness_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::TimeBasedRandomness,
        SecuritySeverity::High,
        0,
        "Time-based randomness detected".to_string(),
        vec![Operation::Random {
            source: "timestamp".to_string(),
        }],
        "Do not use block.timestamp as a source of randomness".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a safe contract with no timestamp dependency vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create circuit with no warnings
    let circuit = TimestampDependencyCircuit::<ark_bn254::Fr>::with_warnings(
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
    
    // Print the number of constraints
    println!("Number of constraints: {}", cs.num_constraints());
    
    // Check if the constraint system is satisfied
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 3);
    
    // Check the number of input variables
    assert_eq!(cs.num_instance_variables(), 1);
    
    // Check the number of witness variables
    assert_eq!(cs.num_witness_variables(), 4);
}

#[test]
fn test_block_timestamp_dependency() {
    // Create contract with block timestamp dependency
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for block timestamp dependency
    let warning = create_block_timestamp_warning();
    
    // Create circuit with block timestamp dependency
    let circuit = TimestampDependencyCircuit::<ark_bn254::Fr>::with_warnings(
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
    
    // Print the number of constraints
    println!("Number of constraints: {}", cs.num_constraints());
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_unsafe_timestamp_comparison() {
    // Create contract with unsafe timestamp comparison
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for unsafe timestamp comparison
    let warning = create_unsafe_comparison_warning();
    
    // Create circuit with unsafe timestamp comparison
    let circuit = TimestampDependencyCircuit::<ark_bn254::Fr>::with_warnings(
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
    
    // Print the number of constraints
    println!("Number of constraints: {}", cs.num_constraints());
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_time_based_randomness() {
    // Create contract with time-based randomness
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for time-based randomness
    let warning = create_time_randomness_warning();
    
    // Create circuit with time-based randomness
    let circuit = TimestampDependencyCircuit::<ark_bn254::Fr>::with_warnings(
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
    
    // Print the number of constraints
    println!("Number of constraints: {}", cs.num_constraints());
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn test_multiple_timestamp_vulnerabilities() {
    // Create contract with multiple timestamp vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warnings for multiple vulnerabilities
    let block_timestamp_warning = create_block_timestamp_warning();
    let unsafe_comparison_warning = create_unsafe_comparison_warning();
    let time_randomness_warning = create_time_randomness_warning();
    
    // Create circuit with multiple vulnerabilities
    let circuit = TimestampDependencyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![block_timestamp_warning],
        vec![unsafe_comparison_warning],
        vec![time_randomness_warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Print the number of constraints
    println!("Number of constraints: {}", cs.num_constraints());
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}
