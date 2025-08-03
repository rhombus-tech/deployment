use ark_relations::r1cs::ConstraintSystem;
use ethers::types::{H160 as Address, H256};

use evm_verify::circuits::reentrancy::ReentrancyCircuit;
use evm_verify::common::DeploymentData;
use evm_verify::bytecode::types::RuntimeAnalysis;
use evm_verify::bytecode::security::SecurityWarning;
use ark_relations::r1cs::ConstraintSynthesizer;

#[test]
fn test_reentrancy_circuit_safe() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create circuit with no warnings
    let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![],
        vec![],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_reentrancy_circuit_classic_vulnerable() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for classic reentrancy
    let warning = SecurityWarning::reentrancy(0, H256::zero());
    
    // Create circuit with warning
    let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
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
fn test_reentrancy_circuit_cross_contract_vulnerable() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warning for cross-contract reentrancy
    let warning = SecurityWarning::cross_contract_reentrancy(
        0, 
        H256::zero(),
        H256::zero(),
    );
    
    // Create circuit with warning
    let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
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
fn test_reentrancy_circuit_multiple_vulnerabilities() {
    // Create deployment data
    let deployment = DeploymentData {
        owner: Address::zero(),
    };
    
    // Create runtime analysis
    let runtime = RuntimeAnalysis::default();
    
    // Create warnings for both classic and cross-contract reentrancy
    let classic_warning = SecurityWarning::reentrancy(0, H256::zero());
    let cross_contract_warning = SecurityWarning::cross_contract_reentrancy(
        0, 
        H256::zero(),
        H256::zero(),
    );
    
    // Create circuit with both warnings
    let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
        deployment,
        runtime,
        vec![classic_warning],
        vec![cross_contract_warning],
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
    
    // Generate constraints
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Check if the constraint system is satisfied (should not be)
    assert!(!cs.is_satisfied().unwrap());
}
