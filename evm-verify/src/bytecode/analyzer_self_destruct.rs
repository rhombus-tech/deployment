use anyhow::Result;
use ethers::types::H256;

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::analyzer::BytecodeAnalyzer;

impl BytecodeAnalyzer {
    /// Detect unprotected self-destruct operations
    pub fn detect_self_destruct(&self) -> Result<Vec<SecurityWarning>> {
        let mut warnings = Vec::new();
        
        // Skip detection in test mode
        if self.is_test_mode() {
            println!("Skipping self-destruct detection in test mode");
            return Ok(warnings);
        }
        
        let bytecode_vec = self.get_bytecode_vec();
        
        // Look for SELFDESTRUCT opcode (0xFF)
        for i in 0..bytecode_vec.len() {
            if bytecode_vec[i] == 0xFF { // SELFDESTRUCT opcode
                // Check if there's access control before the self-destruct
                let is_protected = self.has_access_control_before(i, &bytecode_vec);
                
                if !is_protected {
                    // In a real implementation, we would extract the beneficiary from the stack
                    let beneficiary = H256::random();
                    
                    let warning = SecurityWarning::unprotected_self_destruct(
                        i as u64,
                        beneficiary
                    );
                    
                    println!("Adding unprotected self-destruct warning at position {}", i);
                    warnings.push(warning);
                }
            }
        }
        
        Ok(warnings)
    }
    
    /// Helper method to check if there's access control before a certain position
    fn has_access_control_before(&self, position: usize, bytecode: &[u8]) -> bool {
        // Look back up to 50 instructions to check for access control patterns
        let start = if position > 50 { position - 50 } else { 0 };
        
        // Common access control patterns:
        // 1. CALLER (0x33) followed by comparison with a storage value (typically owner address)
        // 2. SLOAD (0x54) followed by comparison operations
        
        let mut has_caller = false;
        let mut has_sload = false;
        let mut has_comparison = false;
        
        for i in start..position {
            match bytecode[i] {
                0x33 => has_caller = true, // CALLER
                0x54 => has_sload = true,  // SLOAD
                // Comparison opcodes
                0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 => { // LT, GT, SLT, SGT, EQ, ISZERO
                    has_comparison = true;
                },
                // JUMPI - conditional jump, often used after comparison for access control
                0x57 => {
                    if has_caller && has_comparison {
                        return true;
                    }
                    if has_sload && has_comparison {
                        return true;
                    }
                },
                _ => {}
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_unprotected_self_destruct() {
        // Create a simple bytecode with an unprotected SELFDESTRUCT
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xFF); // SELFDESTRUCT
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_self_destruct().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::UnprotectedSelfDestruct);
    }
    
    #[test]
    fn test_detect_protected_self_destruct() {
        // Create a bytecode with a protected SELFDESTRUCT
        // This is a simplified example with basic access control pattern
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x33); // CALLER
        bytecode.push(0x54); // SLOAD (loading owner from storage)
        bytecode.push(0x14); // EQ (comparing caller with owner)
        bytecode.push(0x57); // JUMPI (conditional jump based on comparison)
        bytecode.push(0xFF); // SELFDESTRUCT
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_self_destruct().unwrap();
        
        assert_eq!(warnings.len(), 0); // No warnings as SELFDESTRUCT is protected
    }
    
    #[test]
    fn test_self_destruct_detection_test_mode() {
        // Create a simple bytecode with an unprotected SELFDESTRUCT
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xFF); // SELFDESTRUCT
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        let warnings = analyzer.detect_self_destruct().unwrap();
        
        assert_eq!(warnings.len(), 0); // No warnings in test mode
    }
}
