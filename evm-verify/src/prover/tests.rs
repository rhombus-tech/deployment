use super::*;
use crate::bytecode::{
    AccessPattern,
    StorageAccess,
    RuntimeAnalysis,
    AnalysisResults,
};
use common::DeploymentData;
use ethers::types::{Bytes, H256, Address, U256};

/// Helper to create test bytecode
fn create_test_bytecode(code: Vec<u8>) -> Bytes {
    Bytes::from(code)
}

/// Helper to create test deployment data
fn create_test_deployment(
    creation_code: Vec<u8>,
    constructor_args: Vec<u8>,
    runtime_code: Vec<u8>,
    storage: Vec<StorageAccess>,
    access_patterns: Vec<AccessPattern>,
    owner: Option<Address>,
) -> DeploymentData {
    DeploymentData {
        creation_code: create_test_bytecode(creation_code),
        constructor_args: create_test_bytecode(constructor_args),
        runtime_code: create_test_bytecode(runtime_code),
        storage,
        access_patterns,
        owner,
    }
}

#[test]
fn test_simple_constructor() -> Result<()> {
    // Simple contract that just sets an owner
    let deployment = create_test_deployment(
        vec![0x60, 0x80, 0x60, 0x40], // PUSH1 80 PUSH1 40
        vec![],                        // No constructor args
        vec![0x60, 0x00, 0x80],       // Simple runtime code
        vec![],                        // No storage initialization
        vec![],                        // No access patterns
        Some(Address::random()),
    );

    let circuit = DeploymentCircuit::new(deployment);
    let keys = generate_deployment_keys(&circuit)?;
    let proof = generate_deployment_proof(&circuit, &keys)?;
    
    let public_inputs = vec![Fr::from(1u64)];
    assert!(verify_deployment_proof(&proof, &keys, &public_inputs)?);

    Ok(())
}

#[test]
fn test_constructor_with_args() -> Result<()> {
    let owner = Address::random();
    let owner_bytes: Vec<u8> = owner.as_bytes().to_vec();
    
    // Contract that takes owner address as constructor arg
    let deployment = create_test_deployment(
        vec![
            0x60, 0x80,             // PUSH1 80
            0x60, 0x40,             // PUSH1 40
            0x80, 0x35,             // DUP1 CALLDATALOAD
            0x60, 0x00, 0x55,       // PUSH1 0 SSTORE
        ],
        owner_bytes,                // Owner address as constructor arg
        vec![0x60, 0x00, 0x54],    // Runtime code that loads owner
        vec![
            StorageAccess {
                slot: H256::zero(),
                value: Some(H256::from_slice(&owner.as_bytes())),
                is_init: true,
            },
        ],
        vec![
            AccessPattern {
                protected_slot: H256::zero(),
                allowed_address: Some(H256::from_slice(&owner.as_bytes())),
                condition: "owner == msg.sender".to_string(),
            },
        ],
        Some(owner),
    );

    let circuit = DeploymentCircuit::new(deployment);
    let keys = generate_deployment_keys(&circuit)?;
    let proof = generate_deployment_proof(&circuit, &keys)?;
    
    let public_inputs = vec![Fr::from(1u64)];
    assert!(verify_deployment_proof(&proof, &keys, &public_inputs)?);

    Ok(())
}

#[test]
fn test_complex_storage() -> Result<()> {
    let owner = Address::random();
    let initial_supply = U256::from(1000000u64);
    
    // ERC20-like contract with initial supply
    let deployment = create_test_deployment(
        vec![
            0x60, 0x80,             // PUSH1 80
            0x60, 0x40,             // PUSH1 40
            0x80, 0x35,             // DUP1 CALLDATALOAD
            0x60, 0x00, 0x55,       // PUSH1 0 SSTORE (owner)
            0x60, 0x01, 0x55,       // PUSH1 1 SSTORE (supply)
        ],
        owner.as_bytes().to_vec(),
        vec![0x60, 0x00, 0x54],    // Runtime code
        vec![
            // Owner storage
            StorageAccess {
                slot: H256::zero(),
                value: Some(H256::from_slice(&owner.as_bytes())),
                is_init: true,
            },
            // Total supply storage
            StorageAccess {
                slot: H256::from_low_u64_be(1),
                value: Some(H256::from_uint(&initial_supply)),
                is_init: true,
            },
        ],
        vec![
            // Owner access pattern
            AccessPattern {
                protected_slot: H256::zero(),
                allowed_address: Some(H256::from_slice(&owner.as_bytes())),
                condition: "owner == msg.sender".to_string(),
            },
            // Supply access pattern
            AccessPattern {
                protected_slot: H256::from_low_u64_be(1),
                allowed_address: Some(H256::from_slice(&owner.as_bytes())),
                condition: "owner == msg.sender".to_string(),
            },
        ],
        Some(owner),
    );

    let circuit = DeploymentCircuit::new(deployment);
    let keys = generate_deployment_keys(&circuit)?;
    let proof = generate_deployment_proof(&circuit, &keys)?;
    
    let public_inputs = vec![Fr::from(1u64)];
    assert!(verify_deployment_proof(&proof, &keys, &public_inputs)?);

    Ok(())
}

#[test]
fn test_invalid_storage_access() -> Result<()> {
    let owner = Address::random();
    let attacker = Address::random();
    
    // Try to set attacker as allowed address for owner storage
    let deployment = create_test_deployment(
        vec![0x60, 0x80, 0x60, 0x40],
        vec![],
        vec![0x60, 0x00, 0x54],
        vec![
            StorageAccess {
                slot: H256::zero(),
                value: Some(H256::from_slice(&owner.as_bytes())),
                is_init: true,
            },
        ],
        vec![
            AccessPattern {
                protected_slot: H256::zero(),
                allowed_address: Some(H256::from_slice(&attacker.as_bytes())), // Invalid!
                condition: "owner == msg.sender".to_string(),
            },
        ],
        Some(owner),
    );

    let circuit = DeploymentCircuit::new(deployment);
    let keys = generate_deployment_keys(&circuit)?;
    
    // Should fail to generate proof
    assert!(generate_deployment_proof(&circuit, &keys).is_err());

    Ok(())
}

#[test]
fn test_missing_owner() -> Result<()> {
    // Contract with owner-only function but no owner set
    let deployment = create_test_deployment(
        vec![0x60, 0x80, 0x60, 0x40],
        vec![],
        vec![0x60, 0x00, 0x54],
        vec![],
        vec![
            AccessPattern {
                protected_slot: H256::zero(),
                allowed_address: None,
                condition: "owner == msg.sender".to_string(),
            },
        ],
        None, // No owner set
    );

    let circuit = DeploymentCircuit::new(deployment);
    let keys = generate_deployment_keys(&circuit)?;
    
    // Should fail to generate proof
    assert!(generate_deployment_proof(&circuit, &keys).is_err());

    Ok(())
}

#[test]
fn test_uninitialized_storage() -> Result<()> {
    let owner = Address::random();
    
    // Try to access uninitialized storage
    let deployment = create_test_deployment(
        vec![0x60, 0x80, 0x60, 0x40],
        vec![],
        vec![0x60, 0x00, 0x54],
        vec![
            StorageAccess {
                slot: H256::from_low_u64_be(1), // Access slot 1
                value: Some(H256::from_low_u64_be(123)),
                is_init: false, // Not initialized!
            },
        ],
        vec![],
        Some(owner),
    );

    let circuit = DeploymentCircuit::new(deployment);
    let keys = generate_deployment_keys(&circuit)?;
    
    // Should fail to generate proof
    assert!(generate_deployment_proof(&circuit, &keys).is_err());

    Ok(())
}
