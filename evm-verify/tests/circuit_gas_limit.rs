use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::gas_limit::GasLimitCircuit;
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

// Helper function to create a gas limit dependency warning
fn create_gas_limit_dependency_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("BlockGasLimitDependence".to_string()),
        SecuritySeverity::Medium,
        0,
        "Block gas limit dependence detected".to_string(),
        vec![Operation::BlockInformation {
            info_type: "gas_limit".to_string(),
        }],
        "Avoid relying on block gas limit for critical contract logic".to_string(),
    )
}

// Helper function to create a gas-intensive loop warning
fn create_gas_intensive_loop_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("GasIntensiveLoop".to_string()),
        SecuritySeverity::Medium,
        0,
        "Gas-intensive loop detected".to_string(),
        vec![Operation::Computation {
            op_type: "gas_intensive_loop".to_string(),
            gas_cost: 10000,
        }],
        "Consider implementing gas optimizations for loops".to_string(),
    )
}

// Helper function to create an unbounded operation warning
fn create_unbounded_operation_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("UnboundedOperation".to_string()),
        SecuritySeverity::High,
        0,
        "Unbounded operation detected".to_string(),
        vec![Operation::Computation {
            op_type: "unbounded_operation".to_string(),
            gas_cost: 50000,
        }],
        "Implement bounds for operations to prevent gas limit issues".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a circuit with no vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let circuit = GasLimitCircuit::<ark_bn254::Fr>::new(deployment, runtime);

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is satisfied (no vulnerabilities)
    assert!(cs.is_satisfied().unwrap());

    // Check that we have exactly 3 constraints
    assert_eq!(cs.num_constraints(), 3);

    // Check that we have 4 witness variables (3 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 4);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_gas_limit_dependency() {
    // Create a circuit with gas limit dependency
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_gas_limit_dependency_warning();
    
    let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
        vec![],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is not satisfied (has vulnerabilities)
    assert!(!cs.is_satisfied().unwrap());

    // Check that we have exactly 3 constraints
    assert_eq!(cs.num_constraints(), 3);

    // Check that we have 4 witness variables
    assert_eq!(cs.num_witness_variables(), 4);

    // Check that we have 1 instance variable
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_gas_intensive_loops() {
    // Create a circuit with gas-intensive loops
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_gas_intensive_loop_warning();
    
    let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![warning],
        vec![],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is not satisfied (has vulnerabilities)
    assert!(!cs.is_satisfied().unwrap());

    // Check that we have exactly 3 constraints
    assert_eq!(cs.num_constraints(), 3);
}

#[test]
fn test_unbounded_operations() {
    // Create a circuit with unbounded operations
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_unbounded_operation_warning();
    
    let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
        vec![warning],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is not satisfied (has vulnerabilities)
    assert!(!cs.is_satisfied().unwrap());

    // Check that we have exactly 3 constraints
    assert_eq!(cs.num_constraints(), 3);
}

#[test]
fn test_multiple_gas_limit_vulnerabilities() {
    // Create a circuit with multiple vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning1 = create_gas_limit_dependency_warning();
    let warning2 = create_gas_intensive_loop_warning();
    let warning3 = create_unbounded_operation_warning();
    
    let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning1],
        vec![warning2],
        vec![warning3],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is not satisfied (has vulnerabilities)
    assert!(!cs.is_satisfied().unwrap());

    // Check that we have exactly 3 constraints
    assert_eq!(cs.num_constraints(), 3);
}
