// Governance Attack Vector Analyzer
//
// This module analyzes EVM bytecode to detect vulnerabilities in governance mechanisms
// that could lead to takeovers or manipulation.

use ethers::types::Bytes;
use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::bytecode::opcodes::*;

/// Detects governance vulnerabilities in bytecode
pub fn detect_governance_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    
    // Get the bytecode as a vector of bytes
    let bytecode = analyzer.get_bytecode_vec();
    
    println!("Detecting governance vulnerabilities...");
    
    // Check for insufficient timelock mechanisms
    if has_insufficient_timelock(&bytecode) {
        println!("Insufficient timelock detected, adding warning");
        warnings.push(SecurityWarning::insufficient_timelock(0));
    } else {
        println!("No insufficient timelock detected");
    }
    
    // Check for weak quorum requirements
    if has_weak_quorum_requirements(&bytecode) {
        println!("Weak quorum requirements detected, adding warning");
        warnings.push(SecurityWarning::weak_quorum_requirement(0));
    } else {
        println!("No weak quorum requirements detected");
    }
    
    // Check for flash loan vulnerability in voting
    if has_flash_loan_voting_vulnerability(&bytecode) {
        println!("Flash loan voting vulnerability detected, adding warning");
        warnings.push(SecurityWarning::flash_loan_voting_vulnerability(0));
    } else {
        println!("No flash loan voting vulnerability detected");
    }
    
    // Check for centralized admin controls
    if has_centralized_admin_controls(&bytecode) {
        println!("Centralized admin controls detected, adding warning");
        warnings.push(SecurityWarning::centralized_admin_control(0));
    } else {
        println!("No centralized admin controls detected");
    }
    
    println!("Number of warnings: {}", warnings.len());
    for (i, warning) in warnings.iter().enumerate() {
        println!("Warning {}: {}", i, warning.description);
    }
    
    warnings
}

/// Determines if the contract has insufficient timelock mechanisms
fn has_insufficient_timelock(bytecode: &[u8]) -> bool {
    // Look for timestamp comparisons with small values
    // This is a heuristic approach - in real code, we'd do more sophisticated analysis
    
    println!("Bytecode length: {}", bytecode.len());
    for i in 0..bytecode.len() {
        println!("Index {}: Opcode: {:02X}", i, bytecode[i]);
    }
    
    // Check for TIMESTAMP opcode followed by small value comparison
    for i in 0..bytecode.len().saturating_sub(3) {
        if bytecode[i] == TIMESTAMP {
            println!("Found TIMESTAMP at index {}", i);
            // Check for comparison with a small value (e.g., PUSH1 <small_value> LT/GT/EQ)
            if i+2 < bytecode.len() && bytecode[i+1] == PUSH1 {
                println!("Found PUSH1 at index {}", i+1);
                if i+3 < bytecode.len() &&
                   (bytecode[i+3] == LT || bytecode[i+3] == GT || 
                    bytecode[i+3] == EQ) {
                    println!("Found comparison opcode at index {}: {:02X}", i+3, bytecode[i+3]);
                    // The value is the byte at i+2
                    let value = bytecode[i+2];
                    println!("Value at index {}: {}", i+2, value);
                    // Consider timelock insufficient if it's 60 seconds or less
                    if value <= 60 {
                        println!("Value {} is <= 60, returning true", value);
                        return true;
                    }
                }
            }
        }
    }
    
    println!("No insufficient timelock found, returning false");
    false
}

/// Determines if the contract has weak quorum requirements
fn has_weak_quorum_requirements(bytecode: &[u8]) -> bool {
    // Look for percentage calculations that might indicate quorum checks
    // This is a heuristic approach - in real code, we'd do more sophisticated analysis
    
    // Check for small percentage in quorum requirements (e.g., PUSH1 10 DIV)
    for i in 0..bytecode.len().saturating_sub(3) {
        if bytecode[i] == DIV {
            // Check for comparison with a small percentage (10% or less)
            if i+3 < bytecode.len() && bytecode[i+1] == PUSH1 {
                // Check for small percentage (10% or less)
                if bytecode[i+2] <= 10 {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Determines if the contract has flash loan vulnerability in voting
fn has_flash_loan_voting_vulnerability(bytecode: &[u8]) -> bool {
    // Look for balance checks without timestamp validation
    // This is a heuristic approach - in real code, we'd do more sophisticated analysis
    
    // Check for CALLER followed by BALANCE without timestamp checks
    for i in 0..bytecode.len().saturating_sub(2) {
        if bytecode[i] == CALLER && bytecode[i+1] == PUSH1 {
            // Found a potential address comparison (might be checking caller against admin)
            // Now look for BALANCE opcode without TIMESTAMP nearby
            let mut has_balance = false;
            let mut has_timestamp = false;
            
            // Check next 20 opcodes for BALANCE without TIMESTAMP
            for j in i+2..std::cmp::min(i+20, bytecode.len()) {
                if bytecode[j] == BALANCE {
                    has_balance = true;
                }
                if bytecode[j] == TIMESTAMP {
                    has_timestamp = true;
                }
            }
            
            if has_balance && !has_timestamp {
                return true;
            }
        }
    }
    
    false
}

/// Determines if the contract has centralized admin controls
fn has_centralized_admin_controls(bytecode: &[u8]) -> bool {
    // Look for hardcoded address comparisons
    // This is a heuristic approach - in real code, we'd do more sophisticated analysis
    
    println!("Checking for centralized admin controls...");
    
    // Check for address comparisons (CALLER followed by PUSH operation and EQ)
    for i in 0..bytecode.len().saturating_sub(3) {
        if bytecode[i] == CALLER {
            println!("Found CALLER at index {}", i);
            
            // Check if next opcode is any PUSH operation
            if i+1 < bytecode.len() && is_push_operation(bytecode[i+1]) {
                println!("Found PUSH operation at index {}: {:02X}", i+1, bytecode[i+1]);
                
                // Skip the push data
                let push_size = get_push_size(bytecode[i+1]);
                println!("Push size: {}", push_size);
                
                // The next index after the PUSH operation and its data
                let next_index = i + 2 + push_size;
                println!("Next index: {}", next_index);
                
                // Check if EQ follows the push data
                if next_index < bytecode.len() && bytecode[next_index] == EQ {
                    println!("Found EQ at index {}", next_index);
                    return true;
                } else if next_index < bytecode.len() {
                    println!("Opcode at index {}: {:02X} (expected EQ: {:02X})", next_index, bytecode[next_index], EQ);
                }
            }
        }
    }
    
    println!("No centralized admin controls found");
    false
}

/// Helper function to check if an opcode is a PUSH operation
fn is_push_operation(opcode: u8) -> bool {
    opcode >= PUSH1 && opcode <= (PUSH1 + 31) // PUSH1 to PUSH32
}

/// Helper function to get the size of a PUSH operation
fn get_push_size(opcode: u8) -> usize {
    if is_push_operation(opcode) {
        (opcode - PUSH1 + 1) as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_governance_vulnerabilities() {
        // Create a test bytecode with governance vulnerabilities
        let bytecode = vec![
            // Insufficient timelock (TIMESTAMP, PUSH1 10, GT)
            TIMESTAMP, PUSH1, 10, GT,
            
            // Some filler opcodes
            PUSH1, 0, PUSH1, 0, ADD,
            
            // Weak quorum (DIV, PUSH1 100, PUSH1 10, LT)
            DIV, PUSH1, 100, PUSH1, 10, LT,
            
            // Some filler opcodes
            PUSH1, 0, PUSH1, 0, ADD,
            
            // Centralized admin (CALLER, PUSH1 followed by address comparison)
            CALLER, PUSH1, 0, EQ
        ];
        
        let analyzer = BytecodeAnalyzer::new(bytecode.into());
        
        let warnings = detect_governance_vulnerabilities(&analyzer);
        
        // We should have detected at least one vulnerability
        assert!(!warnings.is_empty());
        
        // Check that we detected the correct vulnerability types
        let has_timelock_warning = warnings.iter().any(|w| 
            w.description.contains("timelock"));
        
        assert!(has_timelock_warning, "Should have detected insufficient timelock");
    }
    
    #[test]
    fn test_safe_governance_contract() {
        // Create a test bytecode without governance vulnerabilities
        let bytecode = vec![
            // Sufficient timelock (TIMESTAMP, PUSH1, 0x15, PUSH1, 0x18, GT) - 0x1518 = 5400 seconds
            TIMESTAMP, PUSH1, 0x15, PUSH1, 0x18, GT,
            
            // Some filler opcodes
            PUSH1, 0, PUSH1, 0, ADD,
            
            // Strong quorum requirement (e.g., 51%)
            PUSH1, 51, PUSH1, 100, DIV,
            
            // No centralized admin control pattern
            JUMPDEST, PUSH1, 0x01, PUSH1, 0x02, ADD,
        ];
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        // Test the governance vulnerability detection
        let warnings = detect_governance_vulnerabilities(&analyzer);
        
        // Verify no vulnerabilities were found
        assert!(warnings.is_empty());
    }
    
    #[test]
    fn test_vulnerable_governance_contract() {
        // Create a test bytecode with governance vulnerabilities
        let bytecode = vec![
            // Insufficient timelock (TIMESTAMP, PUSH1, 0x05, GT) - only 5 seconds
            TIMESTAMP, PUSH1, 0x05, GT,
            
            // Some filler opcodes
            PUSH1, 0, PUSH1, 0, ADD,
            
            // Weak quorum requirement (e.g., 10%)
            PUSH1, 10, PUSH1, 100, DIV,
            
            // Centralized admin control pattern (CALLER, PUSH1, <address>, EQ)
            CALLER, PUSH1, 0xAA, EQ,
        ];
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        // Test the governance vulnerability detection
        let warnings = detect_governance_vulnerabilities(&analyzer);
        
        println!("Test - Number of warnings: {}", warnings.len());
        for (i, warning) in warnings.iter().enumerate() {
            println!("Test - Warning {}: {}", i, warning.description);
            println!("Test - Warning {} kind: {:?}", i, warning.kind);
        }
        
        // Verify vulnerabilities were found
        assert!(!warnings.is_empty(), "Should find at least one vulnerability");
        
        // Check that we have at least the insufficient timelock warning
        let has_timelock_warning = warnings.iter().any(|w| {
            println!("Checking warning: {}", w.description);
            println!("Contains 'Insufficient timelock': {}", w.description.contains("Insufficient timelock"));
            w.description.contains("Insufficient timelock")
        });
        assert!(has_timelock_warning, "Should detect insufficient timelock");
        
        // Check that we have the centralized admin control warning
        let has_admin_warning = warnings.iter().any(|w| 
            w.description.contains("Centralized admin control"));
        assert!(has_admin_warning, "Should detect centralized admin control");
    }
}
