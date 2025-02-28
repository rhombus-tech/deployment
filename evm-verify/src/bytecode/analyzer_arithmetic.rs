use anyhow::Result;

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use crate::bytecode::analyzer::BytecodeAnalyzer;

impl BytecodeAnalyzer {
    /// Detect arithmetic overflow/underflow vulnerabilities with enhanced heuristics
    pub fn detect_arithmetic_overflow_enhanced(&self) -> Result<Vec<SecurityWarning>> {
        let mut warnings = Vec::new();
        
        // Skip detection in test mode
        if self.is_test_mode() {
            println!("Skipping enhanced arithmetic overflow detection in test mode");
            return Ok(warnings);
        }
        
        let bytecode_vec = self.get_bytecode_vec();
        
        // Look for arithmetic operations without overflow checks
        for i in 0..bytecode_vec.len() {
            match bytecode_vec[i] {
                // Arithmetic operations
                0x01 => check_arithmetic_operation(i, "ADD", &bytecode_vec, &mut warnings),
                0x02 => check_arithmetic_operation(i, "MUL", &bytecode_vec, &mut warnings),
                0x03 => check_arithmetic_operation(i, "SUB", &bytecode_vec, &mut warnings),
                0x04 => check_arithmetic_operation(i, "DIV", &bytecode_vec, &mut warnings), // Division by zero
                0x05 => check_arithmetic_operation(i, "SDIV", &bytecode_vec, &mut warnings), // Signed division
                0x06 => check_arithmetic_operation(i, "MOD", &bytecode_vec, &mut warnings), // Modulo by zero
                0x07 => check_arithmetic_operation(i, "SMOD", &bytecode_vec, &mut warnings), // Signed modulo
                0x08 => check_arithmetic_operation(i, "ADDMOD", &bytecode_vec, &mut warnings),
                0x09 => check_arithmetic_operation(i, "MULMOD", &bytecode_vec, &mut warnings),
                0x0A => check_arithmetic_operation(i, "EXP", &bytecode_vec, &mut warnings), // Exponentiation
                _ => {}
            }
        }
        
        Ok(warnings)
    }
}

/// Check if an arithmetic operation is properly checked for overflow/underflow
fn check_arithmetic_operation(
    pc: usize,
    operation: &str,
    bytecode: &[u8],
    warnings: &mut Vec<SecurityWarning>
) {
    // Look ahead for overflow checks (simplified heuristic)
    let mut has_check = false;
    
    // Check for common overflow check patterns within the next 5 opcodes
    for j in 1..=5 {
        if pc + j >= bytecode.len() {
            break;
        }
        
        match bytecode[pc + j] {
            // Common overflow check patterns
            0x10 | 0x11 | 0x12 | 0x13 => has_check = true, // LT, GT, SLT, SGT - comparison
            0x16 | 0x17 => has_check = true, // AND, OR - bit operations often used in checks
            0x60..=0x7F => {}, // PUSH operations - could be part of a check, but need more context
            _ => {}
        }
    }
    
    // Look for DUP operations before arithmetic, which might indicate SafeMath usage
    let mut has_dup_before = false;
    for j in 1..=3 {
        if pc >= j && (0x80..=0x8F).contains(&bytecode[pc - j]) {
            has_dup_before = true;
            break;
        }
    }
    
    // If no check is found and no DUP before (potential SafeMath), create a warning
    if !has_check && !has_dup_before {
        let (severity, description, remediation) = match operation {
            "DIV" | "SDIV" | "MOD" | "SMOD" => (
                SecuritySeverity::High,
                format!("Potential division by zero in {} operation at position {}", operation, pc),
                "Always check the divisor is not zero before performing division operations.".to_string()
            ),
            "ADD" | "MUL" => (
                SecuritySeverity::Medium,
                format!("Potential arithmetic overflow in {} operation at position {}", operation, pc),
                "Use SafeMath library or Solidity 0.8+ with built-in overflow checks for arithmetic operations.".to_string()
            ),
            "SUB" => (
                SecuritySeverity::Medium,
                format!("Potential arithmetic underflow in SUB operation at position {}", pc),
                "Use SafeMath library or Solidity 0.8+ with built-in underflow checks for subtraction operations.".to_string()
            ),
            _ => (
                SecuritySeverity::Low,
                format!("Potential arithmetic issue in {} operation at position {}", operation, pc),
                "Review the arithmetic operation for potential edge cases and ensure proper bounds checking.".to_string()
            )
        };
        
        let warning = SecurityWarning::new(
            SecurityWarningKind::IntegerOverflow,
            severity,
            pc as u64,
            description,
            vec![Operation::Arithmetic { operation: operation.to_string() }],
            remediation,
        );
        
        println!("Adding arithmetic warning at position {}: {}", pc, warning.description);
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_arithmetic_overflow_enhanced() {
        // Create a simple bytecode with unchecked ADD operation
        let bytecode = vec![0x01]; // ADD without checks
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_arithmetic_overflow_enhanced().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::IntegerOverflow);
        assert_eq!(warnings[0].severity, SecuritySeverity::Medium);
        
        // Create a bytecode with ADD followed by comparison (check)
        let bytecode = vec![0x01, 0x10]; // ADD followed by LT comparison
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_arithmetic_overflow_enhanced().unwrap();
        
        assert_eq!(warnings.len(), 0); // No warning because there's a check
        
        // Create a bytecode with DIV operation (division by zero risk)
        let bytecode = vec![0x04]; // DIV without checks
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_arithmetic_overflow_enhanced().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::IntegerOverflow);
        assert_eq!(warnings[0].severity, SecuritySeverity::High); // Division by zero is high severity
    }
    
    #[test]
    fn test_arithmetic_overflow_enhanced_test_mode() {
        // Create a simple bytecode with unchecked ADD operation
        let bytecode = vec![0x01]; // ADD without checks
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        
        let warnings = analyzer.detect_arithmetic_overflow_enhanced().unwrap();
        
        // Should be empty because test mode is enabled
        assert_eq!(warnings.len(), 0);
    }
}
