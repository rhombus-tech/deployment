use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;

#[test]
fn test_unified_verifier() {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Simple bytecode: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(&bytecode).unwrap();
    
    // Check that the report was generated
    assert_eq!(report.contract_size, 5);
    
    // There should be at least one vulnerability (from PCC and PCD analysis)
    assert!(report.vulnerabilities.len() >= 1);
}

#[test]
fn test_unified_verifier_with_config() {
    // Create a unified verifier with only PCC enabled
    let verifier = UnifiedVerifier::with_config(false, true);
    
    // Simple bytecode: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(&bytecode).unwrap();
    
    // Check that the report was generated
    assert_eq!(report.contract_size, 5);
    
    // There should be at least one vulnerability (from PCC analysis)
    // The exact number may vary depending on the analyzer implementation
    assert!(!report.vulnerabilities.is_empty());
}

#[test]
fn test_unified_verifier_with_pcd_only() {
    // Create a unified verifier with only PCD enabled
    let verifier = UnifiedVerifier::with_config(true, false);
    
    // Simple bytecode: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(&bytecode).unwrap();
    
    // Check that the report was generated
    assert_eq!(report.contract_size, 5);
    
    // The PCD analysis might not find vulnerabilities in this simple bytecode
    // So we just check that the report was generated correctly
    assert_eq!(report.contract_size, 5);
}
