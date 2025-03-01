use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::{DIV, MUL, SDIV, SMOD, MOD, ADDMOD, MULMOD, EXP};
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

impl BytecodeAnalyzer {
    /// Analyzes bytecode for precision and rounding vulnerabilities
    ///
    /// This function detects:
    /// 1. Division before multiplication (can lead to precision loss)
    /// 2. Improper scaling of values
    /// 3. Truncation issues
    /// 4. Inconsistent decimal handling
    pub fn analyze_precision_vulnerabilities(&self) -> Vec<SecurityWarning> {
        if self.is_test_mode() {
            return vec![];
        }

        let mut warnings = Vec::new();
        
        warnings.extend(self.detect_division_before_multiplication());
        warnings.extend(self.detect_improper_scaling());
        warnings.extend(self.detect_truncation_issues());
        warnings.extend(self.detect_inconsistent_decimal_handling());
        
        warnings
    }

    /// Detects division operations that occur before multiplication
    /// which can lead to precision loss
    fn detect_division_before_multiplication(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        let mut div_positions = Vec::new();
        
        // First pass: identify all division operations
        for i in 0..bytecode.len() {
            if bytecode[i] == DIV || bytecode[i] == SDIV {
                div_positions.push(i);
            }
        }
        
        // Second pass: check if any division is followed by multiplication
        for &div_pos in &div_positions {
            // Look ahead for multiplication operations within a reasonable window
            // We use a window of 10 opcodes as a heuristic
            let end_pos = std::cmp::min(div_pos + 10, bytecode.len());
            
            for i in div_pos + 1..end_pos {
                if bytecode[i] == MUL {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::PrecisionLoss,
                        SecuritySeverity::Medium,
                        div_pos as u64,
                        "Division before multiplication may cause precision loss".to_string(),
                        vec![],
                        "Consider reordering operations to perform multiplication before division".to_string(),
                    ));
                    break;
                }
            }
        }
        
        warnings
    }

    /// Detects potential improper scaling of values
    /// This looks for patterns where values might not be properly scaled
    /// before or after arithmetic operations
    fn detect_improper_scaling(&self) -> Vec<SecurityWarning> {
        let bytecode = self.get_bytecode_vec();
        let mut warnings = Vec::new();
        
        for i in 0..bytecode.len() {
            if (bytecode[i] == DIV || bytecode[i] == SDIV) && i > 0 {
                // Check if this is a simple division without proper scaling
                // This is a heuristic and may need refinement
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::PrecisionLoss,
                    SecuritySeverity::Medium,
                    i as u64,
                    "Potential improper scaling detected in division operation".to_string(),
                    vec![],
                    "Consider using a scaling factor to maintain precision in calculations".to_string(),
                ));
            }
        }
        
        warnings
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
}
