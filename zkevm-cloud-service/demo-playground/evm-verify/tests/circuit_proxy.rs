use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::proxy::ProxyCircuit;
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

// Helper function to create an uninitialized proxy warning
fn create_uninitialized_proxy_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UninitializedProxy,
        SecuritySeverity::High,
        0,
        "Potential uninitialized proxy vulnerability detected".to_string(),
        vec![Operation::Storage {
            op_type: "implementation_slot".to_string(),
            key: None,
        }],
        "Implement proper checks to ensure the implementation address is initialized before use".to_string(),
    )
}

// Helper function to create a storage collision warning
fn create_storage_collision_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::StorageCollision,
        SecuritySeverity::Medium,
        0,
        "Potential storage collision vulnerability in proxy contract".to_string(),
        vec![Operation::Storage {
            op_type: "proxy_storage".to_string(),
            key: None,
        }],
        "Use unstructured storage pattern or EIP-1967 storage slots to avoid collisions".to_string(),
    )
}

// Helper function to create an implementation shadowing warning
fn create_implementation_shadowing_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::ImplementationShadowing,
        SecuritySeverity::Medium,
        0,
        "Potential implementation shadowing vulnerability in proxy contract".to_string(),
        vec![Operation::Storage {
            op_type: "function_selector".to_string(),
            key: None,
        }],
        "Implement function selector checks to prevent implementation from shadowing proxy admin functions".to_string(),
    )
}

// Helper function to create a self-destruct in proxy warning
fn create_selfdestruct_proxy_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::UninitializedProxy,
        SecuritySeverity::Critical,
        0,
        "Potential self-destruct vulnerability in proxy contract".to_string(),
        vec![Operation::SelfDestruct {
            beneficiary: ethers::types::H256::zero(),
        }],
        "Remove self-destruct functionality from proxy contracts to prevent permanent destruction".to_string(),
    )
}

#[test]
fn test_safe_proxy_contract() {
    // Create a safe contract with no proxy vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create circuit with no warnings
    let circuit = ProxyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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
    assert_eq!(cs.num_constraints(), 10);
    
    // Check the number of input variables
    assert_eq!(cs.num_instance_variables(), 1);
    
    // Check the number of witness variables
    assert_eq!(cs.num_witness_variables(), 5);
}

#[test]
fn test_uninitialized_proxy_vulnerability() {
    // Create contract with uninitialized proxy vulnerability
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for uninitialized proxy
    let warning = create_uninitialized_proxy_warning();
    
    // Create circuit with uninitialized proxy vulnerability
    let circuit = ProxyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
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
fn test_storage_collision_vulnerability() {
    // Create contract with storage collision vulnerability
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for storage collision
    let warning = create_storage_collision_warning();
    
    // Create circuit with storage collision vulnerability
    let circuit = ProxyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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
fn test_implementation_shadowing_vulnerability() {
    // Create contract with implementation shadowing vulnerability
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for implementation shadowing
    let warning = create_implementation_shadowing_warning();
    
    // Create circuit with implementation shadowing vulnerability
    let circuit = ProxyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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
fn test_selfdestruct_in_proxy_vulnerability() {
    // Create contract with self-destruct in proxy vulnerability
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warning for self-destruct in proxy
    let warning = create_selfdestruct_proxy_warning();
    
    // Create circuit with self-destruct in proxy vulnerability
    let circuit = ProxyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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
fn test_multiple_proxy_vulnerabilities() {
    // Create contract with multiple proxy vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    // Create warnings for multiple vulnerabilities
    let uninitialized_warning = create_uninitialized_proxy_warning();
    let storage_warning = create_storage_collision_warning();
    let shadowing_warning = create_implementation_shadowing_warning();
    let selfdestruct_warning = create_selfdestruct_proxy_warning();
    
    // Create circuit with multiple vulnerabilities
    let circuit = ProxyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![uninitialized_warning],
        vec![storage_warning],
        vec![shadowing_warning],
        vec![selfdestruct_warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}
