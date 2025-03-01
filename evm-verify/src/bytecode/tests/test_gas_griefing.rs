use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::analyzer_gas_griefing;
use crate::bytecode::security::SecurityWarningKind;
use ethers::types::Bytes;

#[test]
fn test_unbounded_loops_detection() {
    // Bytecode with an unbounded loop pattern
    // This is a simplified example that includes:
    // - JUMPDEST (loop start)
    // - Some operations including SLOAD (dynamic condition)
    // - PUSH1 (jump target)
    // - JUMPI (conditional jump back to JUMPDEST)
    let bytecode = Bytes::from(vec![
        0x5b, // JUMPDEST
        0x60, 0x01, // PUSH1 1
        0x54, // SLOAD (load from storage)
        0x60, 0x00, // PUSH1 0
        0x57, // JUMPI (jump if condition)
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(false);
    let warnings = analyzer_gas_griefing::analyze(&analyzer);
    
    // We should detect the unbounded loop
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::GasGriefing));
}

#[test]
fn test_expensive_operations_in_loops() {
    // Bytecode with a loop containing expensive operations
    // This is a simplified example that includes:
    // - JUMPDEST (loop start)
    // - Some operations
    // - SSTORE (expensive operation)
    // - PUSH1 (jump target)
    // - JUMP (jump back to JUMPDEST)
    let bytecode = Bytes::from(vec![
        0x5b, // JUMPDEST
        0x60, 0x01, // PUSH1 1
        0x55, // SSTORE (store to storage - expensive)
        0x60, 0x00, // PUSH1 0 (pointing to JUMPDEST)
        0x56, // JUMP (unconditional jump)
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(false);
    let warnings = analyzer_gas_griefing::analyze(&analyzer);
    
    // We should detect the expensive operation in a loop
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::GasGriefing));
}

#[test]
fn test_missing_gas_limits() {
    // Bytecode with a CALL without explicit gas limit
    // This is a simplified example that includes:
    // - GAS opcode (get remaining gas)
    // - Some PUSH operations for other CALL parameters
    // - CALL opcode
    let bytecode = Bytes::from(vec![
        0x5a, // GAS (get all available gas)
        0x60, 0x01, // PUSH1 1 (value)
        0x60, 0x02, // PUSH1 2 (to address - simplified)
        0x60, 0x00, // PUSH1 0 (in offset)
        0x60, 0x00, // PUSH1 0 (in size)
        0x60, 0x00, // PUSH1 0 (out offset)
        0x60, 0x00, // PUSH1 0 (out size)
        0xf1, // CALL
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(false);
    let warnings = analyzer_gas_griefing::analyze(&analyzer);
    
    // We should detect the missing gas limit
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::GasGriefing));
}

#[test]
fn test_insufficient_gas_stipends() {
    // Bytecode with a CALL with insufficient gas stipend
    // This is a simplified example that includes:
    // - PUSH1 with a value <= 2300 (insufficient gas stipend)
    // - Some PUSH operations for other CALL parameters
    // - CALL opcode
    let bytecode = Bytes::from(vec![
        0x60, 0x01, // PUSH1 1 (gas - very low)
        0x60, 0x01, // PUSH1 1 (value)
        0x60, 0x02, // PUSH1 2 (to address - simplified)
        0x60, 0x00, // PUSH1 0 (in offset)
        0x60, 0x00, // PUSH1 0 (in size)
        0x60, 0x00, // PUSH1 0 (out offset)
        0x60, 0x00, // PUSH1 0 (out size)
        0xf1, // CALL
    ]);
    
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(false);
    let warnings = analyzer_gas_griefing::analyze(&analyzer);
    
    // We should detect the insufficient gas stipend
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::GasGriefing));
}

#[test]
fn test_no_warnings_in_test_mode() {
    // Same bytecode as in test_unbounded_loops_detection
    let bytecode = Bytes::from(vec![0x5b, 0x60, 0x01, 0x54, 0x60, 0x00, 0x57]);
    
    // Create analyzer with test_mode = true
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(true);
    let warnings = analyzer_gas_griefing::analyze(&analyzer);
    
    // No warnings should be generated in test mode
    assert!(warnings.is_empty());
}
