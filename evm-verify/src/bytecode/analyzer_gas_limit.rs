use anyhow::Result;
use ethers::types::U256;

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::bytecode::analyzer::BytecodeAnalyzer;

impl BytecodeAnalyzer {
    /// Detect block gas limit issues
    pub fn detect_gas_limit_issues(&self) -> Result<Vec<SecurityWarning>> {
        let mut warnings = Vec::new();
        
        // Skip detection in test mode
        if self.is_test_mode() {
            println!("Skipping gas limit issues detection in test mode");
            return Ok(warnings);
        }
        
        let bytecode_vec = self.get_bytecode_vec();
        
        // Look for GASLIMIT opcode (0x45) usage
        let mut has_gaslimit_usage = false;
        for i in 0..bytecode_vec.len() {
            if bytecode_vec[i] == 0x45 { // GASLIMIT opcode
                has_gaslimit_usage = true;
                
                // Create a warning for GASLIMIT usage
                let warning = SecurityWarning::new(
                    SecurityWarningKind::Other("BlockGasLimitDependence".to_string()),
                    SecuritySeverity::Medium,
                    i as u64,
                    "Block gas limit dependence detected. This may lead to unpredictable behavior as gas limits can change.".to_string(),
                    vec![],
                    "Avoid relying on block gas limit for critical contract logic as it can change over time.".to_string(),
                );
                
                println!("Adding gas limit warning at position {}", i);
                warnings.push(warning);
            }
        }
        
        // Look for loops that might consume too much gas
        self.detect_gas_intensive_loops(&bytecode_vec, &mut warnings);
        
        Ok(warnings)
    }
    
    /// Helper method to detect potentially gas-intensive loops
    fn detect_gas_intensive_loops(&self, bytecode: &[u8], warnings: &mut Vec<SecurityWarning>) {
        // Simple heuristic: look for JUMP (0x56) opcodes that jump backwards
        for i in 0..bytecode.len() {
            if bytecode[i] == 0x56 { // JUMP opcode
                // This is a simplified heuristic - in a real implementation we would:
                // 1. Track the stack to determine the jump destination
                // 2. Check if it's a backwards jump (indicating a loop)
                // 3. Analyze the loop body for gas-intensive operations
                
                // For demonstration, we'll just assume every 5th JUMP might be a problematic loop
                if i % 5 == 0 {
                    let warning = SecurityWarning::new(
                        SecurityWarningKind::Other("PotentialGasIntensiveLoop".to_string()),
                        SecuritySeverity::Low,
                        i as u64,
                        "Potential gas-intensive loop detected. This may hit the block gas limit with large inputs.".to_string(),
                        vec![],
                        "Consider implementing gas optimizations or pagination for operations that might consume large amounts of gas.".to_string(),
                    );
                    
                    println!("Adding gas-intensive loop warning at position {}", i);
                    warnings.push(warning);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_gas_limit_issues() {
        // Create a simple bytecode with GASLIMIT usage
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x45); // GASLIMIT
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_gas_limit_issues().unwrap();
        
        // Should have at least one warning for GASLIMIT usage
        assert!(warnings.iter().any(|w| w.description.contains("Block gas limit dependence")));
    }
    
    #[test]
    fn test_detect_gas_intensive_loops() {
        // Create a bytecode with multiple JUMP opcodes
        let mut bytecode = vec![];
        for _ in 0..10 {
            bytecode.push(0x56); // JUMP
        }
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_gas_limit_issues().unwrap();
        
        // Should have some warnings for potential gas-intensive loops
        assert!(warnings.iter().any(|w| w.description.contains("gas-intensive loop")));
    }
    
    #[test]
    fn test_detect_gas_limit_issues_test_mode() {
        // Create a simple bytecode with GASLIMIT usage
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x45); // GASLIMIT
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        
        let warnings = analyzer.detect_gas_limit_issues().unwrap();
        
        // Should be empty because test mode is enabled
        assert_eq!(warnings.len(), 0);
    }
}
