use ethers::types::Bytes;
use evm_verify::api::{UnifiedVerifier, VulnerabilityType};
use std::str::FromStr;

// Sample bytecode with a reentrancy vulnerability
// SLOAD followed by CALL followed by SSTORE - complete reentrancy pattern
const REENTRANCY_BYTECODE: &str = "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063f8a8fd6d14610046575b600080fd5b34801561005257600080fd5b5061005b61005d565b005b60005460405473ffffffffffffffffffffffffffffffffffffffff1660405180807f7472616e7366657228290000000000000000000000000000000000000000000081525060090190506040518091039020604051809103902060e060020a9004336040518263ffffffff1660e060020a02815260040160006040518083038185885af19350505050506000600181905550565b00";

// Sample bytecode without vulnerabilities
const SAFE_BYTECODE: &str = "608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220223b571f95d38ea9f8dc1a6e1158cb581b4c3bc2adf3c9576e952b2a65a1b89364736f6c63430008070033";

#[test]
fn test_bytecode_verification() {
    // Create a new verifier
    let verifier = UnifiedVerifier::new();
    
    // Test bytecode with reentrancy vulnerability
    let reentrancy_bytes = Bytes::from(hex::decode(REENTRANCY_BYTECODE).unwrap());
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(reentrancy_bytes.clone()).unwrap();
    
    // Check if reentrancy vulnerability is detected
    let has_reentrancy = report.vulnerabilities.iter()
        .any(|v| v.vulnerability_type == VulnerabilityType::Reentrancy);
    
    assert!(has_reentrancy, "Reentrancy vulnerability not detected");
    
    // Generate proof
    let proof = verifier.generate_pcc_proof(&reentrancy_bytes).unwrap();
    
    // Verify proof
    let is_valid = verifier.verify_pcc_proof(&reentrancy_bytes, &proof).unwrap();
    
    assert!(is_valid, "Proof verification failed");
    
    // Test safe bytecode
    let safe_bytes = Bytes::from(hex::decode(SAFE_BYTECODE).unwrap());
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(safe_bytes.clone()).unwrap();
    
    // Check if no reentrancy vulnerability is detected
    let has_reentrancy = report.vulnerabilities.iter()
        .any(|v| v.vulnerability_type == VulnerabilityType::Reentrancy);
    
    assert!(!has_reentrancy, "False positive: Reentrancy vulnerability detected in safe bytecode");
    
    // Generate proof
    let proof = verifier.generate_pcc_proof(&safe_bytes).unwrap();
    
    // Verify proof
    let is_valid = verifier.verify_pcc_proof(&safe_bytes, &proof).unwrap();
    
    assert!(is_valid, "Proof verification failed for safe bytecode");
}

#[test]
fn test_bytecode_integrity() {
    // Create a new verifier
    let verifier = UnifiedVerifier::new();
    
    // Test bytecode with reentrancy vulnerability
    let reentrancy_bytes = Bytes::from(hex::decode(REENTRANCY_BYTECODE).unwrap());
    
    // Generate proof
    let proof = verifier.generate_pcc_proof(&reentrancy_bytes).unwrap();
    
    // Tamper with the bytecode
    let mut tampered_bytes = reentrancy_bytes.to_vec();
    if tampered_bytes.len() > 10 {
        tampered_bytes[10] = tampered_bytes[10].wrapping_add(1);
    }
    let tampered_reentrancy_bytes = Bytes::from(tampered_bytes);
    
    // Verify proof with tampered bytecode
    // This should fail because the bytecode hash won't match
    let is_valid = verifier.verify_pcc_proof(&tampered_reentrancy_bytes, &proof).unwrap();
    
    assert!(!is_valid, "Proof verification should fail with tampered bytecode");
}
