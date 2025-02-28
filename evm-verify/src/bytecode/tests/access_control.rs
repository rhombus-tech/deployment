use ethers::types::Bytes;
use crate::bytecode::BytecodeAnalyzer;

#[test]
fn test_detect_missing_access_control() {
    // Create a simple bytecode with sensitive operations but no access control
    let mut bytecode = vec![0x00]; // STOP
    bytecode.push(0x55); // SSTORE (sensitive operation)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // Should detect the missing access control
    assert!(results.warnings.iter().any(|w| 
        w.contains("access control")
    ));
}

#[test]
fn test_with_access_control() {
    // Create bytecode with access control before sensitive operation
    let mut bytecode = vec![];
    bytecode.push(0x33); // CALLER
    bytecode.push(0x73); // PUSH20 (address)
    // Push 20 bytes for an address
    for _ in 0..20 {
        bytecode.push(0x01);
    }
    bytecode.push(0x14); // EQ (compare)
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x01); // 0x01
    bytecode.push(0x57); // JUMPI (conditional jump)
    bytecode.push(0x55); // SSTORE (sensitive operation)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // Should not detect missing access control
    assert!(!results.warnings.iter().any(|w| 
        w.contains("access control")
    ));
}

#[test]
fn test_access_control_test_mode() {
    // Create a simple bytecode with sensitive operations but no access control
    let mut bytecode = vec![0x00]; // STOP
    bytecode.push(0x55); // SSTORE (sensitive operation)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    analyzer.set_test_mode(true);
    let results = analyzer.analyze().unwrap();
    
    // Should not detect anything in test mode
    assert!(!results.warnings.iter().any(|w| 
        w.contains("access control")
    ));
}
