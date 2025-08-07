use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::{DIV, MUL, SDIV, EXP, MOD, SMOD, ADDMOD, MULMOD, ADD, SUB, PUSH1, LT, GT, EQ, JUMPI};
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use ethers::types::{H256, U256};

impl BytecodeAnalyzer {
    /// Analyzes bytecode for precision and rounding vulnerabilities
    ///
    /// This function detects:
    /// 1. Division before multiplication (can lead to precision loss)
    /// 2. Improper scaling of values
    /// 3. Truncation issues  
    /// 4. Inconsistent decimal handling
    /// 5. Fixed-point arithmetic vulnerabilities
    /// 6. Modular arithmetic precision issues
    pub fn analyze_precision_vulnerabilities(&self) -> Vec<SecurityWarning> {
        if self.is_test_mode() {
            return vec![];
        }

        let mut warnings = Vec::new();
        
        warnings.extend(self.detect_division_before_multiplication());
        warnings.extend(self.detect_improper_scaling());
        warnings.extend(self.detect_truncation_issues());
        warnings.extend(self.detect_inconsistent_decimal_handling());
        warnings.extend(self.detect_fixed_point_arithmetic_issues());
        warnings.extend(self.detect_modular_arithmetic_precision());
        
        warnings
    }

    /// Detects division operations that occur before multiplication with enhanced pattern recognition
    fn detect_division_before_multiplication(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        let mut arithmetic_sequence = Vec::new();
        
        // Track arithmetic operation sequences
        for (i, &opcode) in bytecode.iter().enumerate() {
            match opcode {
                DIV | SDIV => arithmetic_sequence.push((i, "DIV")),
                MUL => arithmetic_sequence.push((i, "MUL")),
                ADD | SUB => arithmetic_sequence.push((i, "ADDSUB")),
                _ => {
                    // Non-arithmetic operation: analyze accumulated sequence
                    if arithmetic_sequence.len() >= 2 {
                        self.analyze_arithmetic_sequence(&arithmetic_sequence, &mut warnings);
                    }
                    arithmetic_sequence.clear();
                }
            }
        }
        
        // Analyze final sequence if it exists
        if arithmetic_sequence.len() >= 2 {
            self.analyze_arithmetic_sequence(&arithmetic_sequence, &mut warnings);
        }
        
        warnings
    }

    /// Analyzes a sequence of arithmetic operations for precision loss patterns
    fn analyze_arithmetic_sequence(&self, sequence: &[(usize, &str)], warnings: &mut Vec<SecurityWarning>) {
        for i in 0..sequence.len()-1 {
            let (pos, op) = sequence[i];
            
            if op == "DIV" {
                // Check if multiplication follows within the sequence
                for j in i+1..sequence.len() {
                    let (mul_pos, next_op) = sequence[j];
                    
                    if next_op == "MUL" {
                        // Calculate risk score based on operation distance and context
                        let distance = mul_pos - pos;
                        let severity = if distance <= 3 {
                            SecuritySeverity::High
                        } else if distance <= 6 {
                            SecuritySeverity::Medium
                        } else {
                            SecuritySeverity::Low
                        };
                        
                        warnings.push(SecurityWarning::new(
                            SecurityWarningKind::PrecisionLoss,
                            severity,
                            pos as u64,
                            format!("Division before multiplication detected (distance: {} opcodes). This can cause precision loss in financial calculations", distance),
                            vec![Operation::Computation {
                                op_type: "div_before_mul".to_string(),
                                gas_cost: 5,
                            }],
                            "Reorder operations to multiply first, then divide. Consider using fixed-point arithmetic libraries for precise decimal calculations".to_string(),
                        ));
                        break;
                    }
                }
            }
        }
    }

    /// Detects potential improper scaling of values with sophisticated analysis
    fn detect_improper_scaling(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        
        // Look for scaling factor patterns
        let scaling_factors = self.identify_scaling_factors(&bytecode);
        
        for i in 0..bytecode.len() {
            if bytecode[i] == DIV || bytecode[i] == SDIV {
                // Check context around division for scaling evidence
                let has_scaling = self.check_scaling_context(i, &bytecode, &scaling_factors);
                
                if !has_scaling {
                    // Look for common precision patterns
                    let risk_level = self.assess_precision_risk(i, &bytecode);
                    
                    if risk_level > 0 {
                        let severity = match risk_level {
                            1 => SecuritySeverity::Low,
                            2 => SecuritySeverity::Medium,
                            _ => SecuritySeverity::High,
                        };
                        
                        warnings.push(SecurityWarning::new(
                            SecurityWarningKind::PrecisionLoss,
                            severity,
                            i as u64,
                            format!("Potential precision loss in division: no scaling factor detected (risk level: {})", risk_level),
                            vec![Operation::Computation {
                                op_type: "unscaled_division".to_string(),
                                gas_cost: 5,
                            }],
                            "Use a scaling factor (e.g., multiply by 10^18) before division to preserve precision. Consider using SafeMath or fixed-point arithmetic libraries".to_string(),
                        ));
                    }
                }
            }
        }
        
        warnings
    }

    /// Identifies common scaling factors in bytecode
    fn identify_scaling_factors(&self, bytecode: &[u8]) -> Vec<u64> {
        let mut scaling_factors = Vec::new();
        let common_factors = vec![100, 1000, 10000, 1000000, 1000000000, 1000000000000000000]; // 10^2 to 10^18
        
        for i in 0..bytecode.len().saturating_sub(2) {
            if bytecode[i] >= PUSH1 && bytecode[i] <= 0x7F {
                let push_size = (bytecode[i] - PUSH1 + 1) as usize;
                if i + push_size < bytecode.len() {
                    // Extract pushed value and check if it's a common scaling factor
                    let mut value = 0u64;
                    for j in 1..=push_size.min(8) {
                        if i + j < bytecode.len() {
                            value = (value << 8) | (bytecode[i + j] as u64);
                        }
                    }
                    
                    if common_factors.contains(&value) {
                        scaling_factors.push(value);
                    }
                }
            }
        }
        
        scaling_factors
    }

    /// Checks if scaling context exists around a division operation
    fn check_scaling_context(&self, div_pos: usize, bytecode: &[u8], scaling_factors: &[u64]) -> bool {
        let window_start = div_pos.saturating_sub(10);
        let window_end = (div_pos + 10).min(bytecode.len());
        
        // Check for multiplication operations near division
        for i in window_start..window_end {
            if bytecode[i] == MUL && !scaling_factors.is_empty() {
                return true;
            }
        }
        
        false
    }

    /// Assesses precision risk level for a division operation
    fn assess_precision_risk(&self, div_pos: usize, bytecode: &[u8]) -> u8 {
        let mut risk_level = 0;
        let window_start = div_pos.saturating_sub(5);
        let window_end = (div_pos + 5).min(bytecode.len());
        
        // Increase risk if division is part of complex calculation
        for i in window_start..window_end {
            match bytecode[i] {
                MUL | ADD | SUB => risk_level += 1,
                EXP => risk_level += 2, // Exponential operations increase precision risk
                MOD | SMOD => risk_level += 1, // Modular operations can affect precision
                0x54 | 0x55 => risk_level += 1, // Storage operations suggest financial context
                _ => {}
            }
        }
        
        risk_level.min(3) // Cap at level 3
    }

    /// Detects potential truncation issues
    /// This looks for patterns where integer division might lead to truncation
    fn detect_truncation_issues(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        
        for i in 0..bytecode.len() {
            if bytecode[i] == DIV || bytecode[i] == SDIV {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::PrecisionLoss,
                    SecuritySeverity::Low,
                    i as u64,
                    "Integer division may cause truncation and precision loss".to_string(),
                    vec![],
                    "Consider using a higher precision representation or scaling factor".to_string(),
                ));
            }
        }
        
        warnings
    }

    /// Detects inconsistent decimal handling
    /// This looks for mixed use of different arithmetic operations that might
    /// indicate inconsistent handling of decimal values
    fn detect_inconsistent_decimal_handling(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        let mut has_div = false;
        let mut has_mul = false;
        let mut has_exp = false;
        
        // First pass: check for presence of different arithmetic operations
        for i in 0..bytecode.len() {
            match bytecode[i] {
                DIV | SDIV => has_div = true,
                MUL => has_mul = true,
                EXP => has_exp = true,
                _ => {}
            }
        }
        
        // If we have a mix of operations, flag as potential inconsistent handling
        if has_div && (has_mul || has_exp) {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::PrecisionLoss,
                SecuritySeverity::Medium,
                0, // We don't have a specific PC for this warning
                "Mixed arithmetic operations may lead to inconsistent decimal handling".to_string(),
                vec![],
                "Review arithmetic operations for consistent precision handling".to_string(),
            ));
        }
        
        // Check for exponentiation which can cause significant precision issues
        if has_exp {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::PrecisionLoss,
                SecuritySeverity::Medium,
                0, // We don't have a specific PC for this warning
                "Exponentiation operations may cause significant precision issues".to_string(),
                vec![],
                "Consider using libraries designed for high-precision math".to_string(),
            ));
        }
        
        warnings
    }

    /// Detects fixed-point arithmetic implementation issues
    fn detect_fixed_point_arithmetic_issues(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        
        // Look for common fixed-point patterns: PUSH large_number, MUL, DIV
        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] >= PUSH1 && bytecode[i] <= 0x7F {
                let push_size = (bytecode[i] - PUSH1 + 1) as usize;
                if i + push_size + 2 < bytecode.len() {
                    if bytecode[i + push_size + 1] == MUL && 
                       self.has_division_nearby(i + push_size + 1, &bytecode) {
                        
                        // Analyze the fixed-point implementation
                        let scaling_factor = self.extract_scaling_factor(i, &bytecode);
                        let risk_level = self.assess_fixed_point_risk(scaling_factor, i, &bytecode);
                        
                        if risk_level > 0 {
                            let severity = match risk_level {
                                1 => SecuritySeverity::Low,
                                2 => SecuritySeverity::Medium,
                                _ => SecuritySeverity::High,
                            };
                            
                            warnings.push(SecurityWarning::new(
                                SecurityWarningKind::PrecisionLoss,
                                severity,
                                i as u64,
                                format!("Potential fixed-point arithmetic issue detected (risk level: {})", risk_level),
                                vec![Operation::Computation {
                                    op_type: "fixed_point_risk".to_string(),
                                    gas_cost: 8,
                                }],
                                "Review fixed-point implementation for overflow/underflow risks. Consider using established fixed-point libraries".to_string(),
                            ));
                        }
                    }
                }
            }
        }
        
        warnings
    }

    /// Detects modular arithmetic precision issues
    fn detect_modular_arithmetic_precision(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        
        for i in 0..bytecode.len() {
            match bytecode[i] {
                MOD | SMOD => {
                    // Check if modular operation could cause precision issues
                    let context_risk = self.analyze_modular_context(i, &bytecode);
                    
                    if context_risk > 1 {
                        let severity = if context_risk >= 3 {
                            SecuritySeverity::Medium
                        } else {
                            SecuritySeverity::Low
                        };
                        
                        warnings.push(SecurityWarning::new(
                            SecurityWarningKind::PrecisionLoss,
                            severity,
                            i as u64,
                            format!("Modular arithmetic may cause precision issues (risk: {})", context_risk),
                            vec![Operation::Computation {
                                op_type: "modular_precision".to_string(),
                                gas_cost: 8,
                            }],
                            "Review modular arithmetic for precision preservation. Consider the mathematical properties of the modulus".to_string(),
                        ));
                    }
                },
                ADDMOD | MULMOD => {
                    // These operations are generally safer but check for edge cases
                    let has_zero_modulus = self.check_zero_modulus_risk(i, &bytecode);
                    
                    if has_zero_modulus {
                        warnings.push(SecurityWarning::new(
                            SecurityWarningKind::PrecisionLoss,
                            SecuritySeverity::High,
                            i as u64,
                            "Modular arithmetic with potential zero modulus detected".to_string(),
                            vec![Operation::Computation {
                                op_type: "zero_modulus_risk".to_string(),
                                gas_cost: 8,
                            }],
                            "Ensure modulus is never zero to prevent division by zero. Add proper input validation".to_string(),
                        ));
                    }
                },
                _ => {}
            }
        }
        
        warnings
    }

    /// Helper methods for fixed-point arithmetic analysis
    fn has_division_nearby(&self, pos: usize, bytecode: &[u8]) -> bool {
        let window_end = (pos + 8).min(bytecode.len());
        for i in pos..window_end {
            if bytecode[i] == DIV || bytecode[i] == SDIV {
                return true;
            }
        }
        false
    }

    fn extract_scaling_factor(&self, pos: usize, bytecode: &[u8]) -> u64 {
        if bytecode[pos] < PUSH1 || bytecode[pos] > 0x7F {
            return 0;
        }
        
        let push_size = (bytecode[pos] - PUSH1 + 1) as usize;
        let mut scaling_factor = 0u64;
        
        for i in 1..=push_size.min(8) {
            if pos + i < bytecode.len() {
                scaling_factor = (scaling_factor << 8) | (bytecode[pos + i] as u64);
            }
        }
        
        scaling_factor
    }

    fn assess_fixed_point_risk(&self, scaling_factor: u64, pos: usize, bytecode: &[u8]) -> u8 {
        let mut risk_level = 0;
        
        // Very large scaling factors increase overflow risk
        if scaling_factor > 1_000_000_000_000_000_000 { // > 10^18
            risk_level += 2;
        } else if scaling_factor > 1_000_000_000 { // > 10^9
            risk_level += 1;
        }
        
        // Check for overflow protection
        let has_overflow_check = self.has_overflow_protection(pos, &bytecode);
        if !has_overflow_check {
            risk_level += 1;
        }
        
        risk_level.min(3)
    }

    fn has_overflow_protection(&self, pos: usize, bytecode: &[u8]) -> bool {
        let window_start = pos.saturating_sub(10);
        let window_end = (pos + 10).min(bytecode.len());
        
        for i in window_start..window_end {
            if bytecode[i] == LT || bytecode[i] == GT || bytecode[i] == EQ {
                if i + 1 < bytecode.len() && bytecode[i + 1] == JUMPI {
                    return true;
                }
            }
        }
        
        false
    }

    fn analyze_modular_context(&self, pos: usize, bytecode: &[u8]) -> u8 {
        let mut risk_level = 0;
        let window_start = pos.saturating_sub(8);
        let window_end = (pos + 8).min(bytecode.len());
        
        for i in window_start..window_end {
            match bytecode[i] {
                DIV | SDIV => risk_level += 2, // Division with modulus increases risk
                MUL => risk_level += 1,
                0x54 | 0x55 => risk_level += 1, // SLOAD/SSTORE suggests financial operation
                _ => {}
            }
        }
        
        risk_level
    }

    fn check_zero_modulus_risk(&self, pos: usize, bytecode: &[u8]) -> bool {
        // Look for patterns that might indicate zero modulus
        // For ADDMOD/MULMOD, the modulus is the third operand on the stack
        // Look back for PUSH1 0 within a reasonable window (up to 10 instructions)
        let start_pos = if pos >= 10 { pos - 10 } else { 0 };
        
        for i in start_pos..pos {
            if i + 1 < bytecode.len() && bytecode[i] == PUSH1 && bytecode[i + 1] == 0 {
                return true;
            }
        }
        false
    }
}

/// Analyzes bytecode for precision and rounding vulnerabilities
///
/// This is the main entry point for precision analysis from the API
///
/// # Arguments
///
/// * `analyzer` - The bytecode analyzer instance
///
/// # Returns
///
/// A vector of security warnings related to precision and rounding vulnerabilities
pub fn analyze(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    analyzer.analyze_precision_vulnerabilities()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;

    #[test]
    fn test_division_before_multiplication() {
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
        assert_eq!(warnings[0].kind, SecurityWarningKind::PrecisionLoss);
        assert_eq!(warnings[0].pc, 4); // DIV operation
    }

    #[test]
    fn test_no_precision_warnings_in_test_mode() {
        let bytecode = Bytes::from(vec![
            0x60, 0x0a, // PUSH1 10
            0x60, 0x02, // PUSH1 2
            0x04,       // DIV (10 / 2 = 5)
            0x60, 0x03, // PUSH1 3
            0x02,       // MUL (5 * 3 = 15)
        ]);
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let warnings = analyzer.analyze_precision_vulnerabilities();
        
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_fixed_point_arithmetic_detection() {
        let bytecode = Bytes::from(vec![
            0x7F, // PUSH32 - large scaling factor (simulate 10^18)
            0x0D, 0xE0, 0xB6, 0xB3, 0xA7, 0x64, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, // MUL - multiply by scaling factor
            0x60, 0x05, // PUSH1 5
            0x04, // DIV - division follows
        ]);
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer.analyze_precision_vulnerabilities();
        
        // Should detect fixed-point pattern
        assert!(!warnings.is_empty());
        assert_eq!(warnings[0].kind, SecurityWarningKind::PrecisionLoss);
    }

    #[test]
    fn test_modular_arithmetic_precision_detection() {
        let bytecode = Bytes::from(vec![
            0x60, 0x64, // PUSH1 100
            0x60, 0x07, // PUSH1 7
            0x06,       // MOD - modular operation
            0x60, 0x05, // PUSH1 5
            0x02,       // MUL - followed by multiplication
        ]);
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer.analyze_precision_vulnerabilities();
        
        // Should detect modular precision issues
        assert!(!warnings.is_empty());
        assert_eq!(warnings[0].kind, SecurityWarningKind::PrecisionLoss);
    }

    #[test]
    fn test_zero_modulus_risk_detection() {
        let bytecode = Bytes::from(vec![
            0x60, 0x00, // PUSH1 0 - zero modulus
            0x60, 0x05, // PUSH1 5
            0x08,       // ADDMOD - modular addition with zero modulus
        ]);
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer.analyze_precision_vulnerabilities();
        
        // Should detect high severity zero modulus risk
        assert!(!warnings.is_empty());
        
        // Find the warning about zero modulus (should be high severity)
        let zero_modulus_warning = warnings.iter()
            .find(|w| w.description.contains("zero modulus"))
            .expect("Should find zero modulus warning");
        
        assert_eq!(zero_modulus_warning.severity, SecuritySeverity::High);
    }

    #[test]
    fn test_enhanced_division_sequence_analysis() {
        let bytecode = Bytes::from(vec![
            0x60, 0x64, // PUSH1 100
            0x60, 0x03, // PUSH1 3
            0x04,       // DIV - division
            0x60, 0x05, // PUSH1 5
            0x02,       // MUL - multiplication follows closely
        ]);
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer.analyze_precision_vulnerabilities();
        
        // Should detect division before multiplication with high severity (close distance)
        assert!(!warnings.is_empty());
        assert_eq!(warnings[0].severity, SecuritySeverity::High);
    }

    #[test]
    fn test_unscaled_division_detection() {
        let bytecode = Bytes::from(vec![
            0x60, 0x64, // PUSH1 100
            0x60, 0x07, // PUSH1 7
            0x04,       // DIV - simple division without scaling
            0x54,       // SLOAD - indicates financial context
            0x55,       // SSTORE
        ]);
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer.analyze_precision_vulnerabilities();
        
        // Should detect unscaled division in financial context
        assert!(!warnings.is_empty());
        assert_eq!(warnings[0].kind, SecurityWarningKind::PrecisionLoss);
    }
}
