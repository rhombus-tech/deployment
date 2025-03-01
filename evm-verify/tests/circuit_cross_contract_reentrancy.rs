use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{H160 as Address, H256};

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::cross_contract_reentrancy::CrossContractReentrancyCircuit;
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

// Helper function to create a direct cross-contract reentrancy warning
fn create_direct_reentrancy_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::CrossContractReentrancy,
        SecuritySeverity::High,
        0,
        "Direct cross-contract reentrancy vulnerability detected".to_string(),
        vec![
            Operation::ExternalCall {
                target: H256::from_low_u64_be(0x1234),
                value: ethers::types::U256::from(0),
                data: vec![0x01, 0x02],
            },
            Operation::StorageWrite {
                slot: H256::zero(),
                value: ethers::types::U256::from(1),
            },
        ],
        "Ensure state changes occur before external calls".to_string(),
    )
}

// Helper function to create an indirect cross-contract reentrancy warning
fn create_indirect_reentrancy_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::CrossContractReentrancy,
        SecuritySeverity::High,
        0,
        "Indirect cross-contract reentrancy vulnerability detected".to_string(),
        vec![
            Operation::ExternalCall {
                target: H256::from_low_u64_be(0x1234),
                value: ethers::types::U256::from(0),
                data: vec![0x01, 0x02],
            },
            Operation::ExternalCall {
                target: H256::from_low_u64_be(0x5678),
                value: ethers::types::U256::from(0),
                data: vec![0x03, 0x04],
            },
            Operation::StorageWrite {
                slot: H256::zero(),
                value: ethers::types::U256::from(1),
            },
        ],
        "Implement reentrancy guards for all external calls".to_string(),
    )
}

// Helper function to create a proxy-based cross-contract reentrancy warning
fn create_proxy_reentrancy_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::CrossContractReentrancy,
        SecuritySeverity::High,
        0,
        "Proxy-based cross-contract reentrancy vulnerability detected".to_string(),
        vec![
            Operation::DelegateCall {
                target: H256::from_low_u64_be(0x1234),
                data: vec![0x01, 0x02],
            },
            Operation::StorageWrite {
                slot: H256::zero(),
                value: ethers::types::U256::from(1),
            },
        ],
        "Implement proper access controls for delegatecall operations".to_string(),
    )
}

// Helper function to create a shared storage cross-contract reentrancy warning
fn create_shared_storage_reentrancy_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::CrossContractReentrancy,
        SecuritySeverity::High,
        0,
        "Shared storage cross-contract reentrancy vulnerability detected".to_string(),
        vec![
            Operation::StorageRead {
                slot: H256::from_low_u64_be(0x1234),
            },
            Operation::ExternalCall {
                target: H256::from_low_u64_be(0x5678),
                value: ethers::types::U256::from(0),
                data: vec![0x03, 0x04],
            },
            Operation::StorageWrite {
                slot: H256::from_low_u64_be(0x1234),
                value: ethers::types::U256::from(1),
            },
        ],
        "Implement proper isolation for shared storage".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a circuit with no vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::new(deployment, runtime);

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is satisfied (no vulnerabilities)
    assert!(cs.is_satisfied().unwrap());

    // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_constraints(), 5);

    // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 5);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_direct_reentrancy() {
    // Create a circuit with direct cross-contract reentrancy
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_direct_reentrancy_warning();
    
    let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
        vec![],
        vec![],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is not satisfied (has vulnerabilities)
    assert!(!cs.is_satisfied().unwrap());

    // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_constraints(), 5);

    // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 5);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_indirect_reentrancy() {
    // Create a circuit with indirect cross-contract reentrancy
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_indirect_reentrancy_warning();
    
    let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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

    // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_constraints(), 5);

    // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 5);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_proxy_reentrancy() {
    // Create a circuit with proxy-based cross-contract reentrancy
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_proxy_reentrancy_warning();
    
    let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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

    // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_constraints(), 5);

    // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 5);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_shared_storage_reentrancy() {
    // Create a circuit with shared storage cross-contract reentrancy
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_shared_storage_reentrancy_warning();
    
    let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
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

    // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_constraints(), 5);

    // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 5);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}

#[test]
fn test_multiple_reentrancy_vulnerabilities() {
    // Create a circuit with multiple cross-contract reentrancy vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let direct_warning = create_direct_reentrancy_warning();
    let indirect_warning = create_indirect_reentrancy_warning();
    let proxy_warning = create_proxy_reentrancy_warning();
    let shared_storage_warning = create_shared_storage_reentrancy_warning();
    
    let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![direct_warning],
        vec![indirect_warning],
        vec![proxy_warning],
        vec![shared_storage_warning],
    );

    // Create a new constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();

    // Check that the circuit is not satisfied (has vulnerabilities)
    assert!(!cs.is_satisfied().unwrap());

    // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_constraints(), 5);

    // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
    assert_eq!(cs.num_witness_variables(), 5);

    // Check that we have 1 instance variable (public input)
    assert_eq!(cs.num_instance_variables(), 1);
}
