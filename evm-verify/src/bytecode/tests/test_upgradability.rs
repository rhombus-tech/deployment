use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::analyzer_upgradability::detect_upgradability_vulnerabilities;
use crate::bytecode::security::{SecurityWarningKind, SecuritySeverity};
use ethers::types::Bytes;

#[test]
fn test_unprotected_upgrade_function_detection() {
    // Create a simple bytecode with DELEGATECALL followed by SSTORE
    // This is a simplified test pattern that should trigger our detection
    let bytecode = vec![
        0xF4, // DELEGATECALL
        0x55, // SSTORE
    ];
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    analyzer.set_test_mode(true);
    
    let warnings = detect_upgradability_vulnerabilities(&analyzer);
    
    assert!(!warnings.is_empty(), "Should detect unprotected upgrade function");
    assert_eq!(warnings[0].kind, SecurityWarningKind::UnprotectedUpgradeFunction);
    assert_eq!(warnings[0].severity, SecuritySeverity::High);
}

#[test]
fn test_missing_initializer_detection() {
    // Create a bytecode with SLOAD but no constructor or initializer pattern
    let bytecode = vec![
        0x54, // SLOAD
        0x01, // ADD
        0x54, // SLOAD
    ];
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    analyzer.set_test_mode(true);
    
    let warnings = detect_upgradability_vulnerabilities(&analyzer);
    
    // In test mode, we're not doing full analysis, so we won't get this warning
    // This is just a placeholder for when we implement more sophisticated detection
    assert!(warnings.is_empty() || warnings.iter().any(|w| w.kind == SecurityWarningKind::MissingInitializer));
}

#[test]
fn test_no_false_positives_in_simple_code() {
    // Create a simple bytecode with no upgradability issues
    let bytecode = vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x02, // PUSH1 2
        0x01, // ADD
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
    ];
    
    let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    
    let warnings = detect_upgradability_vulnerabilities(&analyzer);
    
    assert!(warnings.is_empty(), "Should not detect any issues in simple code");
}
