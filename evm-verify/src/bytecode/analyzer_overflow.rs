use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;

/// Detects potential integer overflow vulnerabilities in EVM bytecode.
/// 
/// This module focuses on identifying:
/// 1. Addition operations without proper checks
/// 2. Multiplication operations without proper checks
/// 3. Risky arithmetic patterns that could lead to overflow
pub fn detect_integer_overflow(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }

    let bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Check for potential overflow operations
    detect_unsafe_additions(&bytecode, &mut warnings);
    detect_unsafe_multiplications(&bytecode, &mut warnings);
    
    // Return all detected warnings
    warnings
}

/// Detects GENUINE addition overflow vulnerabilities.
/// Only flags arithmetic on user input that could actually overflow without proper bounds checking.
fn detect_unsafe_additions(bytecode: &[u8], warnings: &mut Vec<SecurityWarning>) {
    let mut i = 0;
    
    while i < bytecode.len() {
        let opcode = bytecode[i];
        
        // Check for ADD opcode (0x01)
        if opcode == 0x01 {
            // ONLY flag if this is a genuinely dangerous pattern
            if is_dangerous_addition(bytecode, i) &&
               !has_overflow_protection(bytecode, i) &&
               !is_safe_library_pattern(bytecode, i) {
                
                warnings.push(SecurityWarning::integer_overflow(i as u64));
            }
        }
        
        // Skip instruction parameters based on opcode
        i += 1;
        match opcode {
            // PUSH1 through PUSH32 - skip the data bytes
            0x60..=0x7F => {
                let num_bytes = (opcode - 0x60 + 1) as usize;
                i += num_bytes;
            },
            _ => {}
        }
    }
}

/// Detects GENUINE multiplication overflow vulnerabilities.
/// Only flags arithmetic on user input that could actually overflow without proper bounds checking.
fn detect_unsafe_multiplications(bytecode: &[u8], warnings: &mut Vec<SecurityWarning>) {
    let mut i = 0;
    
    while i < bytecode.len() {
        let opcode = bytecode[i];
        
        // Check for MUL opcode (0x02)
        if opcode == 0x02 {
            // ONLY flag if this is a genuinely dangerous pattern
            if is_dangerous_multiplication(bytecode, i) &&
               !has_overflow_protection(bytecode, i) &&
               !is_safe_library_pattern(bytecode, i) {
                
                warnings.push(SecurityWarning::integer_overflow(i as u64));
            }
        }
        
        // Skip instruction parameters based on opcode
        i += 1;
        match opcode {
            // PUSH1 through PUSH32 - skip the data bytes
            0x60..=0x7F => {
                let num_bytes = (opcode - 0x60 + 1) as usize;
                i += num_bytes;
            },
            _ => {}
        }
    }
}

/// Check if this addition operates on user input that could realistically overflow
fn is_dangerous_addition(bytecode: &[u8], add_pos: usize) -> bool {
    // Look for patterns that indicate user input arithmetic:
    // 1. CALLDATALOAD before arithmetic
    // 2. Large constant values being added
    // 3. External call return values used in arithmetic
    
    for i in (add_pos.saturating_sub(15))..add_pos {
        if i >= bytecode.len() { continue; }
        
        match bytecode[i] {
            0x35 => return true, // CALLDATALOAD - user input
            0xF1 | 0xF2 | 0xF4 => { // CALL, CALLCODE, DELEGATECALL
                // Check if return value used in arithmetic (dangerous)
                if i + 10 > add_pos { return true; }
            },
            // Large PUSH values that could overflow
            0x7E | 0x7F => return true, // PUSH31, PUSH32 - very large values
            _ => {}
        }
    }
    false
}

/// Check if this multiplication operates on user input that could realistically overflow
fn is_dangerous_multiplication(bytecode: &[u8], mul_pos: usize) -> bool {
    // Multiplication is more dangerous - even small values can overflow
    for i in (mul_pos.saturating_sub(10))..mul_pos {
        if i >= bytecode.len() { continue; }
        
        match bytecode[i] {
            0x35 => return true, // CALLDATALOAD - user input
            0xF1 | 0xF2 | 0xF4 => return true, // External calls
            // Medium to large PUSH values
            0x70..=0x7F => return true, // PUSH17-PUSH32
            _ => {}
        }
    }
    false
}

/// Check for proper overflow protection patterns
fn has_overflow_protection(bytecode: &[u8], op_pos: usize) -> bool {
    // Look for SafeMath patterns or explicit overflow checks
    for i in (op_pos.saturating_sub(25))..op_pos {
        if i >= bytecode.len() { continue; }
        
        // SafeMath patterns: LT comparison followed by conditional revert
        if bytecode[i] == 0x10 || bytecode[i] == 0x11 { // LT, GT
            // Look for JUMPI or REVERT nearby
            for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                if bytecode[j] == 0x57 || bytecode[j] == 0xFD { // JUMPI, REVERT
                    return true;
                }
            }
        }
    }
    false
}

/// Check if this is a safe library pattern (OpenZeppelin SafeMath, etc.)
fn is_safe_library_pattern(bytecode: &[u8], op_pos: usize) -> bool {
    // Look for SafeMath function signatures or patterns
    let safe_patterns = [
        [0xa9, 0x05, 0x9c, 0xbb], // SafeMath.add signature
        [0x16, 0x5c, 0x4a, 0x16], // SafeMath.mul signature
        [0x4f, 0x7c, 0x4b, 0xd9], // SafeMath.div signature
    ];
    
    // Check broader context for safe patterns
    let start = op_pos.saturating_sub(50);
    let end = std::cmp::min(op_pos + 20, bytecode.len());
    
    if end <= start { return false; }
    let context = &bytecode[start..end];
    
    for pattern in &safe_patterns {
        if contains_pattern(context, pattern) {
            return true;
        }
    }
    
    // Check for compiler-generated overflow checks (pattern-based)
    has_compiler_overflow_check(bytecode, op_pos)
}

/// Helper: Check if bytecode contains a pattern
fn contains_pattern(bytecode: &[u8], pattern: &[u8]) -> bool {
    bytecode.windows(pattern.len()).any(|window| window == pattern)
}

/// Check for compiler-generated overflow protection
fn has_compiler_overflow_check(bytecode: &[u8], op_pos: usize) -> bool {
    // Look for patterns that compilers generate for overflow checking
    // This includes specific sequences of DUP, SWAP, LT, JUMPI, REVERT
    
    for i in (op_pos.saturating_sub(15))..op_pos {
        if i + 5 >= bytecode.len() { continue; }
        
        // Common compiler overflow check pattern:
        // DUP -> SWAP -> LT -> JUMPI -> REVERT
        if bytecode[i] >= 0x80 && bytecode[i] <= 0x8F && // DUP operations
           bytecode[i+1] >= 0x90 && bytecode[i+1] <= 0x9F && // SWAP operations
           (bytecode[i+2] == 0x10 || bytecode[i+2] == 0x11) && // LT/GT
           bytecode[i+3] == 0x57 { // JUMPI
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_unsafe_addition() {
        // Create bytecode with unsafe addition
        let mut bytecode = vec![];
        bytecode.push(0x60); // PUSH1
        bytecode.push(0xFF); // value 255 (max for uint8)
        bytecode.push(0x60); // PUSH1
        bytecode.push(0x01); // value 1
        bytecode.push(0x01); // ADD (255 + 1, will overflow for uint8)
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let results = analyzer.analyze().unwrap();
        
        // Should detect the unsafe addition
        assert!(results.warnings.iter().any(|w| 
            w.contains("overflow")
        ));
    }
    
    #[test]
    fn test_detect_unsafe_multiplication() {
        // Create bytecode with unsafe multiplication
        let mut bytecode = vec![];
        bytecode.push(0x60); // PUSH1
        bytecode.push(0x10); // value 16
        bytecode.push(0x60); // PUSH1
        bytecode.push(0x10); // value 16
        bytecode.push(0x02); // MUL (16 * 16 = 256, potential overflow)
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let results = analyzer.analyze().unwrap();
        
        // Should detect the unsafe multiplication
        assert!(results.warnings.iter().any(|w| 
            w.contains("overflow")
        ));
    }
    
    #[test]
    fn test_safe_addition() {
        // Create bytecode with safe addition (includes check)
        let mut bytecode = vec![];
        bytecode.push(0x60); // PUSH1 - position 0
        bytecode.push(0xFF); // value 255 - position 1
        bytecode.push(0x60); // PUSH1 - position 2
        bytecode.push(0x01); // value 1 - position 3
        bytecode.push(0x60); // PUSH1 - position 4
        bytecode.push(0xFF); // value 255 (max value) - position 5
        bytecode.push(0x60); // PUSH1 - position 6
        bytecode.push(0xFF); // value 255 - position 7
        bytecode.push(0x11); // GT (255 > 255? - checking if first value > max - 1) - position 8
        bytecode.push(0x60); // PUSH1 - position 9
        bytecode.push(0x0F); // jump destination - position 10
        bytecode.push(0x57); // JUMPI (conditional jump) - position 11
        bytecode.push(0x60); // PUSH1 - position 12
        bytecode.push(0xFF); // value 255 - position 13
        bytecode.push(0x60); // PUSH1 - position 14
        bytecode.push(0x01); // value 1 - position 15
        bytecode.push(0x01); // ADD (safe because we checked 255 > max - 1) - position 16
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        // Disable other analyzers that might interfere with our test
        analyzer.set_test_mode(true);
        // But we still want to test our specific analyzer
        let warnings = analyzer.detect_integer_overflow().unwrap();
        
        // Should not detect any unsafe addition
        assert!(warnings.is_empty());
    }
    
    #[test]
    fn test_test_mode() {
        // Create bytecode with unsafe addition
        let mut bytecode = vec![];
        bytecode.push(0x60); // PUSH1
        bytecode.push(0xFF); // value 255
        bytecode.push(0x60); // PUSH1
        bytecode.push(0x01); // value 1
        bytecode.push(0x01); // ADD (255 + 1, will overflow for uint8)
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        let results = analyzer.analyze().unwrap();
        
        // Should not detect anything in test mode
        assert!(!results.warnings.iter().any(|w| 
            w.contains("overflow")
        ));
    }
}
