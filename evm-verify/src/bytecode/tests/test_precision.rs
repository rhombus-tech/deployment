use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::SecurityWarningKind;
use ethers::types::Bytes;

#[test]
fn test_division_before_multiplication() {
    // Bytecode with division followed by multiplication
    // DIV (0x04) followed by MUL (0x02)
    let bytecode = Bytes::from(vec![
        0x60, 0x0a, // PUSH1 10
        0x60, 0x02, // PUSH1 2
        0x04,       // DIV (10 / 2 = 5)
        0x60, 0x03, // PUSH1 3
        0x02,       // MUL (5 * 3 = 15)
    ]);
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.analyze_precision_vulnerabilities();
    
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::PrecisionLoss));
}

#[test]
fn test_improper_scaling() {
    // Bytecode with division followed by storage operation
    // DIV (0x04) followed by SSTORE (0x55)
    let bytecode = Bytes::from(vec![
        0x60, 0x0a, // PUSH1 10
        0x60, 0x02, // PUSH1 2
        0x04,       // DIV (10 / 2 = 5)
        0x60, 0x00, // PUSH1 0 (storage slot)
        0x55,       // SSTORE (store 5 at slot 0)
    ]);
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.analyze_precision_vulnerabilities();
    
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::PrecisionLoss));
}

#[test]
fn test_truncation_issues() {
    // Bytecode with division operation
    let bytecode = Bytes::from(vec![
        0x60, 0x03, // PUSH1 3
        0x60, 0x02, // PUSH1 2
        0x04,       // DIV (3 / 2 = 1, truncated)
    ]);
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.analyze_precision_vulnerabilities();
    
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::PrecisionLoss));
}

#[test]
fn test_inconsistent_decimal_handling() {
    // Bytecode with both regular and modular arithmetic
    let bytecode = Bytes::from(vec![
        0x60, 0x0a, // PUSH1 10
        0x60, 0x03, // PUSH1 3
        0x02,       // MUL (10 * 3 = 30)
        0x60, 0x0a, // PUSH1 10
        0x60, 0x03, // PUSH1 3
        0x60, 0x07, // PUSH1 7
        0x08,       // ADDMOD ((3 + 10) % 7 = 6)
    ]);
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.analyze_precision_vulnerabilities();
    
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::PrecisionLoss));
}

#[test]
fn test_exponentiation_precision_issues() {
    // Bytecode with exponentiation operation
    let bytecode = Bytes::from(vec![
        0x60, 0x02, // PUSH1 2
        0x60, 0x10, // PUSH1 16
        0x0a,       // EXP (2^16 = 65536)
    ]);
    
    let analyzer = BytecodeAnalyzer::new(bytecode);
    let warnings = analyzer.analyze_precision_vulnerabilities();
    
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::PrecisionLoss));
}

#[test]
fn test_no_warnings_in_test_mode() {
    // Bytecode with division followed by multiplication
    // DIV (0x04) followed by MUL (0x02)
    let bytecode = Bytes::from(vec![
        0x60, 0x0a, // PUSH1 10
        0x60, 0x02, // PUSH1 2
        0x04,       // DIV (10 / 2 = 5)
        0x60, 0x03, // PUSH1 3
        0x02,       // MUL (5 * 3 = 15)
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(true); // Enable test mode
    let warnings = analyzer.analyze_precision_vulnerabilities();
    
    assert!(warnings.is_empty());
}
