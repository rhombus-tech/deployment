use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::{H160 as Address, U256, H256};

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::gas_griefing::GasGriefingCircuit;
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

// Helper function to create a forward gas griefing warning
fn create_forward_gas_griefing_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("ForwardGasGriefing".to_string()),
        SecuritySeverity::Medium,
        0,
        "Forward gas griefing vulnerability detected".to_string(),
        vec![Operation::ExternalCall {
            target: H256::from_low_u64_be(0x1234567890),
            value: U256::from(0),
            data: vec![0x01, 0x02], // Minimal call data
        }],
        "Ensure sufficient gas is forwarded to external calls".to_string(),
    )
}

// Helper function to create a gas exhaustion warning
fn create_gas_exhaustion_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("GasExhaustion".to_string()),
        SecuritySeverity::High,
        0,
        "Gas exhaustion vulnerability detected".to_string(),
        vec![Operation::Computation {
            op_type: "gas_exhaustion".to_string(),
            gas_cost: 100000,
        }],
        "Implement gas checks before critical operations".to_string(),
    )
}

// Helper function to create a gas price manipulation warning
fn create_gas_price_manipulation_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("GasPriceManipulation".to_string()),
        SecuritySeverity::Medium,
        0,
        "Gas price manipulation vulnerability detected".to_string(),
        vec![Operation::BlockInformation {
            info_type: "gas_price".to_string(),
        }],
        "Avoid using tx.gasprice for critical logic".to_string(),
    )
}

// Helper function to create a callback gas griefing warning
fn create_callback_gas_griefing_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::Other("CallbackGasGriefing".to_string()),
        SecuritySeverity::High,
        0,
        "Callback gas griefing vulnerability detected".to_string(),
        vec![Operation::ExternalCall {
            target: H256::from_low_u64_be(0x1234567890),
            value: U256::from(0),
            data: vec![0x03, 0x04], // Callback function signature
        }],
        "Ensure callbacks have sufficient gas".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    // Create a circuit with no vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let circuit = GasGriefingCircuit::<ark_bn254::Fr>::new(deployment, runtime);

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
fn test_forward_gas_griefing() {
    // Create a circuit with forward gas griefing
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_forward_gas_griefing_warning();
    
    let circuit = GasGriefingCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_gas_exhaustion() {
    // Create a circuit with gas exhaustion
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_gas_exhaustion_warning();
    
    let circuit = GasGriefingCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_gas_price_manipulation() {
    // Create a circuit with gas price manipulation
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_gas_price_manipulation_warning();
    
    let circuit = GasGriefingCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_callback_gas_griefing() {
    // Create a circuit with callback gas griefing
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_callback_gas_griefing_warning();
    
    let circuit = GasGriefingCircuit::<ark_bn254::Fr>::with_warnings(
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
fn test_multiple_gas_griefing_vulnerabilities() {
    // Create a circuit with multiple vulnerabilities
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let forward_warning = create_forward_gas_griefing_warning();
    let exhaustion_warning = create_gas_exhaustion_warning();
    let price_warning = create_gas_price_manipulation_warning();
    let callback_warning = create_callback_gas_griefing_warning();
    
    let circuit = GasGriefingCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![forward_warning],
        vec![exhaustion_warning],
        vec![price_warning],
        vec![callback_warning],
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
