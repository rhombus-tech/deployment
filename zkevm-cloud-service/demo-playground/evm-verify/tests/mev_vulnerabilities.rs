use anyhow::Result;
use ethers::types::Bytes;
use evm_verify::api::EVMVerify;
use evm_verify::bytecode::security::SecurityWarningKind;

#[test]
fn test_mev_vulnerability_detection() -> Result<()> {
    // Initialize the verifier
    let verifier = EVMVerify::new();
    
    // Test case 1: Bytecode with unprotected price operations
    // This simulates a contract that calls a price oracle without proper protection
    let bytecode_with_vulnerability = Bytes::from(vec![
        // PUSH4 0x50d25bcd (Chainlink latestAnswer selector)
        0x63, 0x50, 0xd2, 0x5b, 0xcd,
        // PUSH1 0 (offset for calldata)
        0x60, 0x00,
        // MSTORE (store selector)
        0x52,
        // PUSH1 4 (size)
        0x60, 0x04,
        // PUSH1 0 (offset)
        0x60, 0x00,
        // PUSH1 0 (value)
        0x60, 0x00,
        // PUSH20 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 (Chainlink ETH/USD feed)
        0x73, 0x5f, 0x4e, 0xC3, 0xDf, 0x9c, 0xbd, 0x43, 0x71, 0x4F, 0xE2,
        0x74, 0x0f, 0x5E, 0x36, 0x16, 0x15, 0x5c, 0x5b, 0x84, 0x19,
        // PUSH1 5000 (gas)
        0x61, 0x13, 0x88,
        // STATICCALL (oracle call)
        0xfa,
        // PUSH1 0 (storage slot)
        0x60, 0x00,
        // SSTORE (store oracle result without slippage protection)
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
        // PUSH4 0x50d25bcd (Chainlink latestAnswer selector)
        0x63, 0x50, 0xd2, 0x5b, 0xcd,
        // PUSH1 0 (offset for calldata)
        0x60, 0x00,
        // MSTORE (store selector)
        0x52,
        // PUSH1 4 (size)
        0x60, 0x04,
        // PUSH1 0 (offset)
        0x60, 0x00,
        // PUSH1 0 (value)
        0x60, 0x00,
        // PUSH20 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 (Chainlink ETH/USD feed)
        0x73, 0x5f, 0x4e, 0xC3, 0xDf, 0x9c, 0xbd, 0x43, 0x71, 0x4F, 0xE2,
        0x74, 0x0f, 0x5E, 0x36, 0x16, 0x15, 0x5c, 0x5b, 0x84, 0x19,
        // PUSH1 5000 (gas)
        0x61, 0x13, 0x88,
        // STATICCALL (oracle call)
        0xfa,
        // PUSH1 0 (storage slot)
        0x60, 0x00,
        // SSTORE (store oracle result without slippage protection)
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
