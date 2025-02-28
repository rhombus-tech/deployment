use crate::bytecode::analyzer::BytecodeAnalyzer;
use ethers::types::Bytes;

#[test]
fn test_detect_block_number_dependency() {
    // Bytecode with NUMBER opcode followed by comparison
    let bytecode = Bytes::from(vec![
        0x43, // NUMBER
        0x60, 0x01, // PUSH1 1
        0x10, // LT
        0x57, // JUMPI
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.detect_block_number_dependency().unwrap();
    
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].description.contains("Block number dependency detected"));
}

#[test]
fn test_safe_block_number_usage() {
    // Bytecode with NUMBER opcode but not used for critical decisions
    let bytecode = Bytes::from(vec![
        0x43, // NUMBER
        0x60, 0x01, // PUSH1 1
        0x01, // ADD
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.detect_block_number_dependency().unwrap();
    
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_block_number_dependency_test_mode() {
    // Bytecode with NUMBER opcode followed by comparison
    let bytecode = Bytes::from(vec![
        0x43, // NUMBER
        0x60, 0x01, // PUSH1 1
        0x10, // LT
        0x57, // JUMPI
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(true);
    let warnings = analyzer.detect_block_number_dependency().unwrap();
    
    // Should be 0 in test mode
    assert_eq!(warnings.len(), 0);
}
