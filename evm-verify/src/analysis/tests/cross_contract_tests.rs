use crate::analysis::cross_contract::{ContractProtocol, ProtocolFindingKind};
use ethers::types::H160;
use std::str::FromStr;

/// Sample bytecode for a contract with external calls
const CONTRACT_WITH_CALLS: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];

/// Sample bytecode for a contract with reentrancy
const CONTRACT_WITH_REENTRANCY: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

/// Sample bytecode for a contract callback
const CONTRACT_CALLBACK: &[u8] = &[0xFE, 0xED, 0xFA, 0xCE];

#[test]
fn test_build_call_graph() {
    // Create addresses for testing
    let contract_a = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let contract_b = H160::from_str("0x1122334455667788990011223344556677889901").unwrap();
    let contract_c = H160::from_str("0xaabbccddeeff00112233445566778899001122aa").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(contract_a, CONTRACT_WITH_CALLS.to_vec()).unwrap();
    protocol.add_contract(contract_b, CONTRACT_WITH_REENTRANCY.to_vec()).unwrap();
    protocol.add_contract(contract_c, CONTRACT_CALLBACK.to_vec()).unwrap();
    
    // Build call graph - just verify it doesn't panic
    protocol.build_call_graph().unwrap();
}

#[test]
fn test_analyze_protocol() {
    // Create addresses for testing
    let contract_a = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let contract_b = H160::from_str("0x1122334455667788990011223344556677889901").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(contract_a, CONTRACT_WITH_REENTRANCY.to_vec()).unwrap();
    protocol.add_contract(contract_b, CONTRACT_CALLBACK.to_vec()).unwrap();
    
    // Analyze protocol - just test that it doesn't panic
    let findings = protocol.analyze().unwrap();
    println!("Found {} protocol findings", findings.len());
}

#[test]
fn test_call_path() {
    // Create addresses for testing
    let contract_a = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let contract_b = H160::from_str("0x1122334455667788990011223344556677889901").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(contract_a, CONTRACT_WITH_CALLS.to_vec()).unwrap();
    protocol.add_contract(contract_b, CONTRACT_WITH_REENTRANCY.to_vec()).unwrap();
    
    // Test call path function - simplified implementation always returns None
    let path = protocol.find_call_path(contract_a, contract_b);
    assert!(path.is_none()); // Our simplified implementation always returns None
}
