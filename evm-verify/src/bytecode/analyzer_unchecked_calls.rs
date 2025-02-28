use anyhow::Result;

use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;

impl BytecodeAnalyzer {
    /// Detect unchecked external calls
    pub fn detect_unchecked_calls(&self) -> Result<Vec<SecurityWarning>> {
        let mut warnings = Vec::new();
        
        // Skip detection in test mode
        if self.is_test_mode() {
            println!("Skipping unchecked calls detection in test mode");
            return Ok(warnings);
        }
        
        let bytecode_vec = self.get_bytecode_vec();
        
        // Look for CALL opcodes (0xF1) and check if return value is checked
        for i in 0..bytecode_vec.len() {
            if bytecode_vec[i] == 0xF1 { // CALL opcode
                // Check if the next few opcodes include ISZERO (0x15) which checks the return value
                let mut return_checked = false;
                
                // Look ahead up to 5 opcodes to see if return value is checked
                for j in 1..=5 {
                    if i + j < bytecode_vec.len() && bytecode_vec[i + j] == 0x15 {
                        return_checked = true;
                        break;
                    }
                }
                
                // If return value is not checked, generate a warning
                if !return_checked {
                    // For simplicity, use default values for target and value
                    // In a real implementation, we would extract these from the stack
                    let warning = SecurityWarning::unchecked_call(i as u64);
                    
                    println!("Adding unchecked call warning at position {}", i);
                    warnings.push(warning);
                }
            }
        }
        
        Ok(warnings)
    }
}

/// Standalone function to detect unchecked calls for API compatibility
pub fn detect_unchecked_calls(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    match analyzer.detect_unchecked_calls() {
        Ok(warnings) => warnings,
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_unchecked_calls() {
        // Create a simple bytecode with an unchecked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // Some other opcode, not ISZERO
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        assert_eq!(warnings.len(), 1);
        
        // Create a bytecode with a checked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x15); // ISZERO - checking the return value
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        assert_eq!(warnings.len(), 0);
    }
    
    #[test]
    fn test_detect_unchecked_calls_test_mode() {
        // Create a simple bytecode with an unchecked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // Some other opcode, not ISZERO
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        // Should be empty because test mode is enabled
        assert_eq!(warnings.len(), 0);
    }
}
