use anyhow::Result;

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::bytecode::analyzer::BytecodeAnalyzer;

impl BytecodeAnalyzer {
    /// Detect tx.origin usage vulnerabilities
    pub fn detect_txorigin_usage(&self) -> Result<Vec<SecurityWarning>> {
        let mut warnings = Vec::new();
        
        // Skip detection in test mode
        if self.is_test_mode() {
            println!("Skipping tx.origin usage detection in test mode");
            return Ok(warnings);
        }
        
        let bytecode_vec = self.get_bytecode_vec();
        
        // Look for ORIGIN opcode (0x32)
        for i in 0..bytecode_vec.len() {
            if bytecode_vec[i] == 0x32 { // ORIGIN opcode
                // Check if it's used for authorization by looking for comparison opcodes
                let mut is_auth = false;
                
                // Look ahead up to 5 opcodes to see if it's used in a comparison
                for j in 1..=5 {
                    if i + j < bytecode_vec.len() {
                        let opcode = bytecode_vec[i + j];
                        // Check for comparison opcodes: EQ (0x14), LT (0x10), GT (0x11)
                        if opcode == 0x14 || opcode == 0x10 || opcode == 0x11 {
                            is_auth = true;
                            break;
                        }
                    }
                }
                
                // Create appropriate warning based on usage pattern
                let warning = if is_auth {
                    // It's likely used for authorization - higher severity
                    SecurityWarning::new(
                        SecurityWarningKind::TxOriginAuth,
                        SecuritySeverity::High,
                        i as u64,
                        "tx.origin used for authorization. This is vulnerable to phishing attacks.".to_string(),
                        vec![],
                        "Use msg.sender instead of tx.origin for authorization checks.".to_string(),
                    )
                } else {
                    // General usage - lower severity
                    SecurityWarning::new(
                        SecurityWarningKind::TxOriginUsage,
                        SecuritySeverity::Medium,
                        i as u64,
                        "tx.origin usage detected. This may lead to security vulnerabilities.".to_string(),
                        vec![],
                        "Avoid using tx.origin as it can lead to phishing vulnerabilities. Use msg.sender instead.".to_string(),
                    )
                };
                
                println!("Adding tx.origin warning at position {}: {}", i, warning.description);
                warnings.push(warning);
            }
        }
        
        Ok(warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_txorigin_usage() {
        // Create a simple bytecode with tx.origin usage
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x32); // ORIGIN
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_txorigin_usage().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::TxOriginUsage);
        
        // Create a bytecode with tx.origin used for authorization
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x32); // ORIGIN
        bytecode.push(0x14); // EQ - comparison
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_txorigin_usage().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::TxOriginAuth);
    }
    
    #[test]
    fn test_detect_txorigin_usage_test_mode() {
        // Create a simple bytecode with tx.origin usage
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x32); // ORIGIN
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        
        let warnings = analyzer.detect_txorigin_usage().unwrap();
        
        // Should be empty because test mode is enabled
        assert_eq!(warnings.len(), 0);
    }
}
