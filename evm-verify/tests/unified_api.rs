use evm_verify::UnifiedVerifier;
use ethers::types::Bytes;

#[test]
fn test_unified_verifier() {
    // Create a unified verifier
    let verifier = UnifiedVerifier::new();
    
    // Simple bytecode: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(bytecode).unwrap();
    
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
    let report = verifier.analyze_bytecode(bytecode).unwrap();
    
    // Check that the report was generated
    assert_eq!(report.contract_size, 5);
    
    // There should be exactly one vulnerability (from PCC analysis)
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.vulnerabilities[0].title.contains("PCC"));
}

#[test]
fn test_unified_verifier_with_pcd_only() {
    // Create a unified verifier with only PCD enabled
    let verifier = UnifiedVerifier::with_config(true, false);
    
    // Simple bytecode: PUSH1 1 PUSH1 0 SSTORE
    let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
    
    // Analyze bytecode
    let report = verifier.analyze_bytecode(bytecode).unwrap();
    
    // Check that the report was generated
    assert_eq!(report.contract_size, 5);
    
    // There should be exactly one vulnerability (from PCD analysis)
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.vulnerabilities[0].title.contains("PCD"));
}
