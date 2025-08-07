use anyhow::Result;
use ethers::types::{H256, U256};

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
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
        let _has_gaslimit_usage = false;
        for i in 0..bytecode_vec.len() {
            if bytecode_vec[i] == 0x45 { // GASLIMIT opcode
                // has_gaslimit_usage = true;
                
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
        // First pass: identify all JUMPDEST opcodes (valid jump targets)
        let mut jump_destinations = std::collections::HashSet::new();
        for i in 0..bytecode.len() {
            if bytecode[i] == 0x5b { // JUMPDEST
                jump_destinations.insert(i);
            }
        }

        // Second pass: analyze jumps and detect loops
        let mut i = 0;
        while i < bytecode.len() {
            match bytecode[i] {
                0x56 => { // JUMP
                    if let Some(destination) = self.extract_jump_destination(bytecode, i) {
                        if destination < i && jump_destinations.contains(&destination) {
                            // Backwards jump detected - potential loop
                            self.analyze_loop_body(bytecode, destination, i, warnings);
                        }
                    }
                    i += 1;
                },
                0x57 => { // JUMPI (conditional jump - common in loops)
                    if let Some(destination) = self.extract_jump_destination(bytecode, i) {
                        if destination < i && jump_destinations.contains(&destination) {
                            // Backwards conditional jump - likely loop
                            self.analyze_loop_body(bytecode, destination, i, warnings);
                        }
                    }
                    i += 1;
                },
                // Skip over PUSH operations and their data
                op if op >= 0x60 && op <= 0x7f => {
                    let push_size = (op - 0x60 + 1) as usize;
                    i += 1 + push_size;
                },
                _ => i += 1,
            }
        }
    }

    /// Extract jump destination from bytecode (simplified stack tracking)
    fn extract_jump_destination(&self, bytecode: &[u8], jump_pos: usize) -> Option<usize> {
        // Look backwards for PUSH instructions that likely contain the jump destination
        let mut pos = jump_pos;
        let mut stack_items = 0;
        
        while pos > 0 && stack_items < 10 { // Limit search to prevent infinite loops
            pos -= 1;
            
            match bytecode[pos] {
                // PUSH1 through PUSH32
                op if op >= 0x60 && op <= 0x7f => {
                    let push_size = (op - 0x60 + 1) as usize;
                    if pos + push_size < bytecode.len() && push_size <= 4 {
                        // Extract the pushed value as potential jump destination
                        let mut dest = 0usize;
                        for j in 1..=push_size {
                            if pos + j < bytecode.len() {
                                dest = (dest << 8) | bytecode[pos + j] as usize;
                            }
                        }
                        if dest < bytecode.len() {
                            return Some(dest);
                        }
                    }
                    // Skip backwards over the push data
                    if pos >= push_size {
                        pos -= push_size;
                    }
                    stack_items += 1;
                },
                _ => {},
            }
        }
        None
    }

    /// Analyze the body of a detected loop for gas-intensive operations
    fn analyze_loop_body(&self, bytecode: &[u8], start: usize, end: usize, warnings: &mut Vec<SecurityWarning>) {
        let mut gas_intensive_ops = 0;
        let mut storage_operations = 0;
        let mut external_calls = 0;
        
        for i in start..end.min(bytecode.len()) {
            match bytecode[i] {
                0x54 => storage_operations += 1,    // SLOAD
                0x55 => storage_operations += 1,    // SSTORE  
                0xf1 => external_calls += 1,        // CALL
                0xf2 => external_calls += 1,        // CALLCODE
                0xf4 => external_calls += 1,        // DELEGATECALL
                0xfa => external_calls += 1,        // STATICCALL
                0xf0 => external_calls += 1,        // CREATE
                0xf5 => external_calls += 1,        // CREATE2
                0x20 => gas_intensive_ops += 1,     // KECCAK256 (SHA3)
                0x3f => gas_intensive_ops += 1,     // EXTCODEHASH
                0x3b => gas_intensive_ops += 1,     // EXTCODESIZE
                0x3c => gas_intensive_ops += 1,     // EXTCODECOPY
                _ => {},
            }
        }

        // Determine severity based on gas-intensive operations found
        let loop_size = end - start;
        let severity = if external_calls > 0 || storage_operations > 3 {
            SecuritySeverity::High
        } else if storage_operations > 1 || gas_intensive_ops > 2 {
            SecuritySeverity::Medium
        } else if gas_intensive_ops > 0 || loop_size > 100 {
            SecuritySeverity::Low
        } else {
            return; // Not gas-intensive enough to warn about
        };

        let mut description_parts = vec![];
        let mut operations = vec![];
        
        if external_calls > 0 {
            description_parts.push(format!("External calls in loop: {}", external_calls));
            // Add representative external call operation
            operations.push(Operation::ExternalCall {
                target: H256::zero(),
                value: U256::zero(),
                data: vec![],
            });
        }
        if storage_operations > 0 {
            description_parts.push(format!("Storage operations in loop: {}", storage_operations));
            // Add representative storage operation
            operations.push(Operation::StorageWrite {
                slot: H256::zero(),
                value: U256::zero(),
            });
        }
        if gas_intensive_ops > 0 {
            description_parts.push(format!("Gas-intensive operations in loop: {}", gas_intensive_ops));
            // Add representative computation operation
            operations.push(Operation::Computation {
                op_type: "KECCAK256".to_string(),
                gas_cost: 30,
            });
        }
        description_parts.push(format!("Loop body size: {} bytes", loop_size));

        let description = format!(
            "Gas-intensive loop detected ({}). Loop contains operations that may consume excessive gas with large inputs.",
            description_parts.join(", ")
        );

        let recommendation = if external_calls > 0 {
            "Critical: External calls in loops can lead to DoS attacks and unpredictable gas consumption. Consider pagination or alternative patterns.".to_string()
        } else if storage_operations > 3 {
            "High risk: Multiple storage operations in loops can quickly exceed block gas limits. Implement batch processing or pagination.".to_string()
        } else {
            "Consider implementing gas optimizations, early exit conditions, or pagination for operations that might consume large amounts of gas.".to_string()
        };

        let warning = SecurityWarning::new(
            SecurityWarningKind::Other("GasIntensiveLoop".to_string()),
            severity,
            start as u64,
            description,
            operations,
            recommendation,
        );
        
        warnings.push(warning);
    }
}

/// Standalone function to detect gas limit vulnerabilities for API compatibility
pub fn detect_gas_limit_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    match analyzer.detect_gas_limit_issues() {
        Ok(warnings) => warnings,
        Err(_) => Vec::new(),
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
        // Create a bytecode that represents a gas-intensive loop:
        // - JUMPDEST at position 0 (loop start)
        // - SLOAD (storage read - gas intensive)
        // - SSTORE (storage write - gas intensive) 
        // - PUSH1 0x00 (push loop destination)
        // - JUMPI (conditional jump back to start)
        let bytecode = vec![
            0x5b,       // JUMPDEST (position 0 - loop start)
            0x54,       // SLOAD (storage read - gas intensive)
            0x55,       // SSTORE (storage write - gas intensive)
            0x60, 0x00, // PUSH1 0x00 (push destination address)
            0x57,       // JUMPI (conditional jump back to 0)
        ];
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_gas_limit_issues().unwrap();
        
        // Should have some warnings for potential gas-intensive loops
        assert!(warnings.iter().any(|w| w.description.contains("Gas-intensive loop detected")));
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
