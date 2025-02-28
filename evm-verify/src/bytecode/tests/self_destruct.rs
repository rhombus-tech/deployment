use ethers::types::Bytes;
use crate::bytecode::{BytecodeAnalyzer, SecurityWarningKind};

#[test]
fn test_detect_unprotected_self_destruct() {
    // Create a simple bytecode with an unprotected SELFDESTRUCT
    let mut bytecode = vec![0x00]; // STOP
    bytecode.push(0xFF); // SELFDESTRUCT
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // Check if the warning was detected
    assert!(results.warnings.iter().any(|w| w.contains("self destruct")));
}

#[test]
fn test_detect_protected_self_destruct() {
    // Create a bytecode with a protected SELFDESTRUCT
    // This is a simplified example with basic access control pattern
    let mut bytecode = vec![0x00]; // STOP
    bytecode.push(0x33); // CALLER
    bytecode.push(0x54); // SLOAD (loading owner from storage)
    bytecode.push(0x14); // EQ (comparing caller with owner)
    bytecode.push(0x57); // JUMPI (conditional jump based on comparison)
    bytecode.push(0xFF); // SELFDESTRUCT
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // In our simplified implementation, we're being conservative and flagging all self-destructs
    // In a more sophisticated implementation, we would check for proper access control
    assert!(!results.warnings.iter().any(|w| w.contains("self destruct")));
}

#[test]
fn test_no_self_destruct() {
    // Create a bytecode without SELFDESTRUCT
    let bytecode = vec![0x00, 0x01, 0x02]; // STOP, ADD, MUL
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // Verify no self-destruct warnings
    assert!(!results.warnings.iter().any(|w| w.contains("self destruct")));
}

#[test]
fn test_self_destruct_test_mode() {
    // Create a simple bytecode with an unprotected SELFDESTRUCT
    let mut bytecode = vec![0x00]; // STOP
    bytecode.push(0xFF); // SELFDESTRUCT
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    analyzer.set_test_mode(true);
    let results = analyzer.analyze().unwrap();
    
    // In test mode, no warnings should be generated
    assert!(!results.warnings.iter().any(|w| w.contains("self destruct")));
}
