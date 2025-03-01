use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::*;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};

/// Detects potential bitmask vulnerabilities in EVM bytecode
pub fn detect_bitmask_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return warnings;
    }
    
    detect_improper_bitmask(analyzer, &mut warnings);
    detect_missing_bitmask(analyzer, &mut warnings);
    
    warnings
}

/// Detects improper use of bitmasks
fn detect_improper_bitmask(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for bitwise operations that might be used incorrectly
        if i + 2 < bytecode.len() && 
           (bytecode[i] == AND as u8 || bytecode[i] == OR as u8 || bytecode[i] == XOR as u8) {
            // Simplified heuristic - in a real analyzer we'd track stack values
            if i + 5 < bytecode.len() && bytecode[i+3] == EQ as u8 {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::BitMaskVulnerability,
                    SecuritySeverity::Medium,
                    i as u64,
                    "Potential improper use of bitmask operation".to_string(),
                    vec![Operation::Computation {
                        op_type: "bitmask".to_string(),
                        gas_cost: 0,
                    }],
                    "Verify that bitwise operations are correctly implemented for the intended purpose".to_string(),
                ));
            }
        }
        
        i += 1;
    }
}

/// Detects missing bitmask operations where they might be needed
fn detect_missing_bitmask(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    // Check for operations that typically require bitmasks but don't have them
    while i < bytecode.len() {
        // Look for operations that might need bitmasks but don't have them
        // This is a simplified heuristic
        if i + 3 < bytecode.len() && 
           bytecode[i] == CALLDATALOAD as u8 &&
           bytecode[i+3] != AND as u8 && 
           bytecode[i+3] != SHR as u8 && 
           bytecode[i+3] != SHL as u8 {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::BitMaskVulnerability,
                SecuritySeverity::Low,
                i as u64,
                "Potential missing bitmask operation on user input".to_string(),
                vec![Operation::Computation {
                    op_type: "missing_bitmask".to_string(),
                    gas_cost: 0,
                }],
                "Consider adding appropriate bitmask operations to sanitize inputs".to_string(),
            ));
            
            // Skip ahead to avoid duplicate warnings
            i += 3;
        }
        
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use ethers::types::Bytes;
    
    #[test]
    fn test_improper_bitmask_detection() {
        // Create bytecode with potentially improper bitmask usage
        let bytecode = vec![
            PUSH1 as u8, 0x01,
            PUSH1 as u8, 0xFF,
            AND as u8,
            PUSH1 as u8, 0x00,
            EQ as u8,
            PUSH1 as u8, 0x00,
            JUMPI as u8,
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(!warnings.is_empty(), "Should detect improper bitmask");
        assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::BitMaskVulnerability), 
                "Should have BitMaskVulnerability warning");
    }
    
    #[test]
    fn test_missing_bitmask_detection() {
        // Create bytecode with potentially missing bitmask
        let bytecode = vec![
            PUSH1 as u8, 0x00,
            CALLDATALOAD as u8,
            PUSH1 as u8, 0x00,
            ADD as u8,  // No bitmask before using the value
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(!warnings.is_empty(), "Should detect missing bitmask");
        assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::BitMaskVulnerability), 
                "Should have BitMaskVulnerability warning");
    }
    
    #[test]
    fn test_proper_bitmask_usage() {
        // Create bytecode with proper bitmask usage
        let bytecode = vec![
            PUSH1 as u8, 0x00,
            CALLDATALOAD as u8,
            PUSH1 as u8, 0xFF,
            AND as u8,  // Proper bitmask
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(warnings.is_empty(), "Should not detect issues with proper bitmask");
    }
    
    #[test]
    fn test_bitmask_test_mode() {
        // Create bytecode with potentially improper bitmask usage
        let bytecode = vec![
            PUSH1 as u8, 0x01,
            PUSH1 as u8, 0xFF,
            AND as u8,
            PUSH1 as u8, 0x00,
            EQ as u8,
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);  // Enable test mode
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(warnings.is_empty(), "Should not detect issues in test mode");
    }
}
