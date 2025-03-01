use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ethers::types::H160 as Address;

use evm_verify::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::circuits::governance::GovernanceCircuit;
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

// Helper function to create an insufficient timelock warning
fn create_insufficient_timelock_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::InsufficientTimelock,
        SecuritySeverity::Medium,
        0,
        "Insufficient timelock detected".to_string(),
        vec![Operation::Timestamp],
        "Implement a longer timelock period for governance actions".to_string(),
    )
}

// Helper function to create a weak quorum requirement warning
fn create_weak_quorum_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::WeakQuorumRequirement,
        SecuritySeverity::Medium,
        0,
        "Weak quorum requirements detected".to_string(),
        vec![Operation::Comparison {
            op_type: "quorum_check".to_string(),
        }],
        "Increase quorum requirements to prevent governance takeovers".to_string(),
    )
}

// Helper function to create a flash loan voting vulnerability warning
fn create_flash_loan_voting_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::FlashLoanVotingVulnerability,
        SecuritySeverity::High,
        0,
        "Flash loan voting vulnerability detected".to_string(),
        vec![Operation::Storage {
            op_type: "voting_power".to_string(),
            key: None,
        }],
        "Implement voting power snapshots or time-locks to prevent flash loan attacks".to_string(),
    )
}

// Helper function to create a centralized admin control warning
fn create_centralized_admin_warning() -> SecurityWarning {
    SecurityWarning::new(
        SecurityWarningKind::CentralizedAdminControl,
        SecuritySeverity::Medium,
        0,
        "Centralized admin control detected".to_string(),
        vec![Operation::Storage {
            op_type: "admin_role".to_string(),
            key: None,
        }],
        "Implement multi-signature or DAO-based governance".to_string(),
    )
}

#[test]
fn test_safe_contract() {
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    
    let circuit = GovernanceCircuit::new(deployment, runtime);
    
    // Create a constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // The circuit should be satisfied since there are no vulnerabilities
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
}

#[test]
fn test_insufficient_timelock() {
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_insufficient_timelock_warning();
    
    let circuit = GovernanceCircuit::with_warnings(
        deployment,
        runtime,
        vec![warning],
        vec![],
        vec![],
        vec![],
    );
    
    // Create a constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // The circuit should not be satisfied due to insufficient timelock
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
}

#[test]
fn test_weak_quorum_requirements() {
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_weak_quorum_warning();
    
    let circuit = GovernanceCircuit::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![warning],
        vec![],
        vec![],
    );
    
    // Create a constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // The circuit should not be satisfied due to weak quorum requirements
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
}

#[test]
fn test_flash_loan_voting_vulnerability() {
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_flash_loan_voting_warning();
    
    let circuit = GovernanceCircuit::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
        vec![warning],
        vec![],
    );
    
    // Create a constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // The circuit should not be satisfied due to flash loan voting vulnerability
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
}

#[test]
fn test_centralized_admin_controls() {
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let warning = create_centralized_admin_warning();
    
    let circuit = GovernanceCircuit::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
        vec![],
        vec![warning],
    );
    
    // Create a constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // The circuit should not be satisfied due to centralized admin controls
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
}

#[test]
fn test_multiple_governance_vulnerabilities() {
    let deployment = create_mock_deployment();
    let runtime = create_mock_runtime();
    let timelock_warning = create_insufficient_timelock_warning();
    let quorum_warning = create_weak_quorum_warning();
    let flash_loan_warning = create_flash_loan_voting_warning();
    
    let circuit = GovernanceCircuit::with_warnings(
        deployment,
        runtime,
        vec![timelock_warning],
        vec![quorum_warning],
        vec![flash_loan_warning],
        vec![],
    );
    
    // Create a constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // The circuit should not be satisfied due to multiple vulnerabilities
    assert!(!cs.is_satisfied().unwrap());
    assert_eq!(cs.num_constraints(), 4);
}
