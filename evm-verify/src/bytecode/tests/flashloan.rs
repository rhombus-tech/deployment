use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::security::SecurityWarningKind;
use crate::bytecode::analyzer_flashloan::detect_flash_loan_vulnerabilities;
use ethers::types::Bytes;
use hex_literal::hex;

#[test]
fn test_detect_price_oracle_dependencies() {
    // Bytecode that simulates an external call followed by price-dependent operations
    // CALL (0xF1) followed by arithmetic operations and SSTORE
    let bytecode = Bytes::from(hex!(
        "60806040526004361061001e5760003560e01c80633bc5de301461011e575b600080fd5b34801561012a57600080fd5b50610133610135565b005b60008060008073ffffffffffffffffffffffffffffffffffffffff1663095ea7b36040518163ffffffff1660e01b815260040160206040518083038186803b15801561018157600080fd5b505afa158015610195573d6000803e3d6000fd5b505050506040513d602081101561020b57600080fd5b81019080805190602001909291905050509050806002600082825401925050819055505050565b"
    ));
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = detect_flash_loan_vulnerabilities(&analyzer);
    
    // Verify that we detected a price oracle dependency vulnerability
    assert!(!warnings.is_empty(), "Should have detected price oracle dependency vulnerability");
    
    // Check that at least one warning is of the correct type
    let has_price_oracle_warning = warnings.iter().any(|w| {
        matches!(w.kind, SecurityWarningKind::FlashLoanVulnerability)
    });
    
    assert!(has_price_oracle_warning, "Should have detected a price oracle dependency vulnerability");
}

#[test]
fn test_detect_state_changes_after_calls() {
    // Bytecode that simulates an external call followed by state changes without validation
    // CALL (0xF1) followed by SSTORE without proper validation
    let bytecode = Bytes::from(hex!(
        "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e9a6a25b14610046575b600080fd5b34801561005257600080fd5b5061005b61005d565b005b600073ffffffffffffffffffffffffffffffffffffffff16738bd8b14e4ec9737e4f7161f50f5235f97c8f8c1a73ffffffffffffffffffffffffffffffffffffffff16141561009e57600080fd5b60008060008073ffffffffffffffffffffffffffffffffffffffff1663095ea7b36040518163ffffffff1660e01b815260040160206040518083038186803b1580156100e957600080fd5b505afa1580156100fd573d6000803e3d6000fd5b505050506040513d602081101561011357600080fd5b810190808051906020019092919050505090508060016000828254019250508190555050505600a165627a7a7230582002e0c8c24f8afa3f2f8f9e7e9202f54e1f1b3f8fec20b7c3543c7273d0d28ebf0029"
    ));
    
    // Print bytecode length for debugging
    println!("State changes test bytecode length: {}", bytecode.len());
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = detect_flash_loan_vulnerabilities(&analyzer);
    
    // Verify that we detected a state change after call vulnerability
    assert!(!warnings.is_empty(), "Should have detected state change after call vulnerability");
    
    // Check that at least one warning is of the correct type
    let has_state_change_warning = warnings.iter().any(|w| {
        matches!(w.kind, SecurityWarningKind::FlashLoanStateManipulation)
    });
    
    assert!(has_state_change_warning, "Should have detected a state change after call vulnerability");
}

#[test]
fn test_detect_missing_slippage_protection() {
    // Bytecode that simulates a swap operation without slippage protection
    // Typically involves CALL with token transfer followed by another CALL without min/max checks
    let bytecode = Bytes::from(hex!(
        "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e9a6a25b14610046575b600080fd5b34801561005257600080fd5b5061005b61005d565b005b600073ffffffffffffffffffffffffffffffffffffffff16738bd8b14e4ec9737e4f7161f50f5235f97c8f8c1a73ffffffffffffffffffffffffffffffffffffffff16141561009e57600080fd5b60008073ffffffffffffffffffffffffffffffffffffffff1663095ea7b36040518163ffffffff1660e01b815260040160206040518083038186803b1580156100e957600080fd5b505afa1580156100fd573d6000803e3d6000fd5b505050506040513d602081101561011357600080fd5b8101908080519060200190929190505050905060008073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb6040518163ffffffff1660e01b815260040160206040518083038186803b15801561016d57600080fd5b505afa158015610181573d6000803e3d6000fd5b505050506040513d602081101561019757600080fd5b81019080805190602001909291905050509050505600a165627a7a7230582002e0c8c24f8afa3f2f8f9e7e9202f54e1f1b3f8fec20b7c3543c7273d0d28ebf0029"
    ));
    
    // Print bytecode length for debugging
    println!("Missing slippage test bytecode length: {}", bytecode.len());
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = detect_flash_loan_vulnerabilities(&analyzer);
    
    // Verify that we detected a missing slippage protection vulnerability
    assert!(!warnings.is_empty(), "Should have detected missing slippage protection vulnerability");
    
    // Check that at least one warning is of the correct type
    let has_slippage_warning = warnings.iter().any(|w| {
        matches!(w.kind, SecurityWarningKind::MissingSlippageProtection)
    });
    
    assert!(has_slippage_warning, "Should have detected a missing slippage protection vulnerability");
}

#[test]
fn test_respects_test_mode() {
    // Bytecode that would normally trigger a flash loan vulnerability
    let bytecode = Bytes::from(hex!(
        "60806040526004361061001e5760003560e01c80633bc5de301461011e575b600080fd5b34801561012a57600080fd5b50610133610135565b005b60008060008073ffffffffffffffffffffffffffffffffffffffff1663095ea7b36040518163ffffffff1660e01b815260040160206040518083038186803b15801561018157600080fd5b505afa158015610195573d6000803e3d6000fd5b505050506040513d602081101561020b57600080fd5b81019080805190602001909291905050509050806002600082825401925050819055505050565b"
    ));
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    
    // Enable test mode
    analyzer.set_test_mode(true);
    
    let warnings = detect_flash_loan_vulnerabilities(&analyzer);
    
    // Verify that no warnings were detected in test mode
    assert!(warnings.is_empty(), "Should not detect vulnerabilities in test mode");
}
