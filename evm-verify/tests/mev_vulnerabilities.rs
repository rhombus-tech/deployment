use anyhow::Result;
use ethers::types::Bytes;
use evm_verify::api::EVMVerify;
use evm_verify::bytecode::security::SecurityWarningKind;

#[test]
fn test_mev_vulnerability_detection() -> Result<()> {
    // Initialize the verifier
    let verifier = EVMVerify::new();
    
    // Test case 1: Bytecode with unprotected price operations
    // This is a simplified example that would trigger the MEV vulnerability detection
    // In a real contract, this would be more complex
    let bytecode_with_vulnerability = Bytes::from(vec![
        // PUSH1 1 (price)
        0x60, 0x01,
        // PUSH1 0 (storage slot)
        0x60, 0x00,
        // SSTORE (store price without checks)
        0x55,
    ]);
    
    // Analyze the bytecode for MEV vulnerabilities
    let warnings = verifier.analyze_mev_vulnerabilities(bytecode_with_vulnerability)?;
    
    // Verify that at least one MEV vulnerability was detected
    assert!(!warnings.is_empty(), "Expected to find MEV vulnerabilities");
    
    // Verify that the detected vulnerability is of the correct type
    let has_mev_vulnerability = warnings.iter().any(|warning| {
        matches!(warning.kind, SecurityWarningKind::MEVVulnerability)
    });
    
    assert!(has_mev_vulnerability, "Expected to find MEVVulnerability warning");
    
    // Test case 2: Bytecode without MEV vulnerabilities
    // This is a simple bytecode that shouldn't trigger any MEV vulnerability detection
    let safe_bytecode = Bytes::from(vec![
        // PUSH1 0
        0x60, 0x00,
        // PUSH1 0
        0x60, 0x00,
        // RETURN
        0xF3,
    ]);
    
    // Analyze the safe bytecode
    let safe_warnings = verifier.analyze_mev_vulnerabilities(safe_bytecode)?;
    
    // Verify that no MEV vulnerabilities were detected
    let has_mev_vulnerability = safe_warnings.iter().any(|warning| {
        matches!(warning.kind, SecurityWarningKind::MEVVulnerability)
    });
    
    assert!(!has_mev_vulnerability, "Expected no MEV vulnerabilities in safe bytecode");
    
    Ok(())
}

#[test]
fn test_mev_vulnerability_with_test_mode() -> Result<()> {
    // Initialize the verifier
    let mut verifier = EVMVerify::new();
    
    // Set test mode to true to disable certain features
    verifier.set_test_mode(true);
    
    // Bytecode with potential MEV vulnerability
    let bytecode = Bytes::from(vec![
        // PUSH1 1 (price)
        0x60, 0x01,
        // PUSH1 0 (storage slot)
        0x60, 0x00,
        // SSTORE (store price without checks)
        0x55,
    ]);
    
    // Analyze the bytecode for MEV vulnerabilities with test mode enabled
    let warnings = verifier.analyze_mev_vulnerabilities(bytecode)?;
    
    // Verify that MEV vulnerabilities are still detected even in test mode
    let has_mev_vulnerability = warnings.iter().any(|warning| {
        matches!(warning.kind, SecurityWarningKind::MEVVulnerability)
    });
    
    assert!(has_mev_vulnerability, "Expected to find MEV vulnerabilities even in test mode");
    
    // Reset test mode
    verifier.set_test_mode(false);
    
    Ok(())
}
