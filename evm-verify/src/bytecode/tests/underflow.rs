use ethers::types::Bytes;
use crate::bytecode::BytecodeAnalyzer;

#[test]
fn test_detect_unsafe_subtraction() {
    // Create bytecode with unsafe subtraction
    let mut bytecode = vec![];
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x05); // value 5
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x0A); // value 10
    bytecode.push(0x03); // SUB (10 - 5, but what if 5 > 10?)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // Should detect the unsafe subtraction
    assert!(results.warnings.iter().any(|w| 
        w.contains("underflow")
    ));
}

#[test]
fn test_safe_subtraction() {
    // Create bytecode with safe subtraction (includes check)
    let mut bytecode = vec![];
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x05); // value 5
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x0A); // value 10
    bytecode.push(0x10); // LT (5 < 10?)
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x0F); // jump destination
    bytecode.push(0x57); // JUMPI (conditional jump)
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x05); // value 5
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x0A); // value 10
    bytecode.push(0x03); // SUB (safe because we checked 5 < 10)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    // Disable other analyzers that might interfere with our test
    analyzer.set_test_mode(true);
    // But we still want to test our specific analyzer
    let warnings = analyzer.detect_integer_underflow().unwrap();
    
    // Should not detect any unsafe subtraction
    assert!(warnings.is_empty());
}

#[test]
fn test_unsafe_decrement() {
    // Create bytecode with unsafe decrement
    let mut bytecode = vec![];
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x01); // value 1
    bytecode.push(0x03); // SUB (decrement by 1 without check)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    let results = analyzer.analyze().unwrap();
    
    // Should detect the unsafe decrement
    assert!(results.warnings.iter().any(|w| 
        w.contains("underflow")
    ));
}

#[test]
fn test_test_mode() {
    // Create bytecode with unsafe subtraction
    let mut bytecode = vec![];
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x05); // value 5
    bytecode.push(0x60); // PUSH1
    bytecode.push(0x0A); // value 10
    bytecode.push(0x03); // SUB (10 - 5, but what if 5 > 10?)
    
    let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
    analyzer.set_test_mode(true);
    let results = analyzer.analyze().unwrap();
    
    // Should not detect anything in test mode
    assert!(!results.warnings.iter().any(|w| 
        w.contains("underflow")
    ));
}
