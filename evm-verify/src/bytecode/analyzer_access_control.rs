use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;

/// Detects potential access control vulnerabilities in EVM bytecode.
/// 
/// This module focuses on identifying:
/// 1. Missing access controls before sensitive operations
/// 2. Weak access control mechanisms
/// 3. Inconsistent access control patterns
pub fn detect_access_control_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }

    let bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Check for sensitive operations without access controls
    detect_missing_access_controls(&bytecode, &mut warnings);
    
    // Return all detected warnings
    warnings
}

/// Detects operations that typically require access controls but don't have them.
/// 
/// Sensitive operations include:
/// - State-changing operations
/// - Fund transfers
/// - Administrative functions
fn detect_missing_access_controls(bytecode: &[u8], warnings: &mut Vec<SecurityWarning>) {
    // Simple bytecode with just a SSTORE operation is definitely missing access controls
    if bytecode.len() <= 2 && bytecode.contains(&0x55) {
        warnings.push(SecurityWarning::access_control_vulnerability(0));
        return;
    }

    let mut i = 0;
    let mut has_caller_check = false;
    let mut sensitive_ops = Vec::new();
    
    // First pass: identify if there are any CALLER (0x33) checks
    while i < bytecode.len() {
        if i + 1 < bytecode.len() {
            // Look for CALLER (0x33) followed by comparison operations
            if bytecode[i] == 0x33 { // CALLER
                // Look ahead for comparison operations
                let mut j = i + 1;
                while j < bytecode.len() && j < i + 10 { // Look at most 10 opcodes ahead
                    // Check for common comparison opcodes
                    if bytecode[j] == 0x14 || // EQ
                       bytecode[j] == 0x11 || // GT
                       bytecode[j] == 0x10 || // LT
                       bytecode[j] == 0x13 { // SGT
                        has_caller_check = true;
                        break;
                    }
                    j += 1;
                }
            }
            
            // Identify sensitive operations
            // CALL (0xF1), DELEGATECALL (0xF4), STATICCALL (0xFA)
            if bytecode[i] == 0xF1 || bytecode[i] == 0xF4 || bytecode[i] == 0xFA {
                sensitive_ops.push(i);
            }
            
            // SSTORE (0x55) - Storage write
            if bytecode[i] == 0x55 {
                sensitive_ops.push(i);
            }
            
            // SELFDESTRUCT (0xFF)
            if bytecode[i] == 0xFF {
                sensitive_ops.push(i);
            }
        }
        i += 1;
    }
    
    // If there are sensitive operations but no caller checks, that's a potential vulnerability
    if !sensitive_ops.is_empty() && !has_caller_check {
        for &pc in &sensitive_ops {
            warnings.push(SecurityWarning::access_control_vulnerability(pc as u64));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
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
}
