use crate::bytecode::analyzer::BytecodeAnalyzer;
use ethers::types::Bytes;

#[test]
fn test_detect_uninitialized_storage() {
    // Bytecode with SLOAD before any SSTORE
    let bytecode = Bytes::from(vec![
        0x60, 0x00, // PUSH1 0
        0x54, // SLOAD
        0x60, 0x01, // PUSH1 1
        0x01, // ADD
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.detect_uninitialized_storage().unwrap();
    
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].description.contains("uninitialized storage"));
}

#[test]
fn test_initialized_storage() {
    // Bytecode with SSTORE before SLOAD
    let bytecode = Bytes::from(vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
        0x60, 0x00, // PUSH1 0
        0x54, // SLOAD
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.detect_uninitialized_storage().unwrap();
    
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_uninitialized_storage_test_mode() {
    // Bytecode with SLOAD before any SSTORE
    let bytecode = Bytes::from(vec![
        0x60, 0x00, // PUSH1 0
        0x54, // SLOAD
        0x60, 0x01, // PUSH1 1
        0x01, // ADD
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(true);
    let warnings = analyzer.detect_uninitialized_storage().unwrap();
    
    // Should be 0 in test mode
    assert_eq!(warnings.len(), 0);
}
