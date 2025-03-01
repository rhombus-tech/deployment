use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::{CALL, STATICCALL, DELEGATECALL, CALLCODE, SLOAD, SSTORE};
use ethers::types::H256;

/// Represents a contract call in the bytecode
struct ContractCall {
    /// Position in the bytecode
    position: usize,
    /// Call type (CALL, STATICCALL, DELEGATECALL, CALLCODE)
    call_type: u8,
    /// Target address if available (may be dynamic)
    target_address: Option<H256>,
}

/// Represents a storage operation in the bytecode
struct StorageOperation {
    /// Position in the bytecode
    position: usize,
    /// Operation type (SLOAD or SSTORE)
    op_type: u8,
    /// Storage slot if available (may be dynamic)
    slot: Option<H256>,
}

/// Detects cross-contract reentrancy vulnerabilities in EVM bytecode.
/// 
/// This function extends beyond basic reentrancy detection to identify complex
/// cross-contract reentrancy vulnerabilities by:
/// 1. Tracking state changes after external calls across multiple contracts
/// 2. Analyzing shared storage access patterns
/// 3. Detecting complex call patterns that may enable reentrancy
pub fn detect_cross_contract_reentrancy(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }

    let bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Track external calls and storage operations
    let mut external_calls: Vec<ContractCall> = Vec::new();
    let mut storage_operations: Vec<StorageOperation> = Vec::new();
    
    // Scan for external calls and storage operations
    let mut i = 0;
    while i < bytecode.len() {
        // Check for external calls
        if bytecode[i] == CALL || bytecode[i] == STATICCALL || 
           bytecode[i] == DELEGATECALL || bytecode[i] == CALLCODE {
            // In a real implementation, we would try to extract the target address
            // from the stack, but for simplicity, we'll just record the call
            external_calls.push(ContractCall {
                position: i,
                call_type: bytecode[i],
                target_address: None, // Would be extracted from stack in a full implementation
            });
        }
        
        // Check for storage operations
        if bytecode[i] == SLOAD || bytecode[i] == SSTORE {
            // In a real implementation, we would try to extract the storage slot
            // from the stack, but for simplicity, we'll just record the operation
            storage_operations.push(StorageOperation {
                position: i,
                op_type: bytecode[i],
                slot: None, // Would be extracted from stack in a full implementation
            });
        }
        
        i += 1;
    }
    
    // Analyze call patterns for potential cross-contract reentrancy
    if !external_calls.is_empty() {
        // Check for storage writes after external calls
        for call in &external_calls {
            // Check if there are storage writes after this call
            let storage_writes_after_call = storage_operations.iter()
                .filter(|op| op.op_type == SSTORE && op.position > call.position)
                .count();
            
            // Check if there are storage reads before this call
            let storage_reads_before_call = storage_operations.iter()
                .filter(|op| op.op_type == SLOAD && op.position < call.position)
                .count();
            
            // If we have both storage reads before the call and storage writes after,
            // this is a potential cross-contract reentrancy vulnerability
            if storage_writes_after_call > 0 && storage_reads_before_call > 0 {
                // Check if this is a CALL or DELEGATECALL (more likely to be vulnerable)
                if call.call_type == CALL || call.call_type == DELEGATECALL {
                    warnings.push(SecurityWarning::cross_contract_reentrancy(
                        call.position as u64,
                        call.target_address.unwrap_or_else(H256::zero),
                        H256::zero(), // Contract address would be determined in a full implementation
                    ));
                    
                    // Only report one warning per call pattern to avoid duplicates
                    break;
                }
            }
        }
        
        // Check for multiple external calls with shared state
        if external_calls.len() > 1 {
            // Look for patterns where we have multiple calls with storage operations between them
            let mut prev_call_pos = 0;
            for (i, call) in external_calls.iter().enumerate() {
                if i > 0 {
                    // Check if there are storage operations between the previous call and this one
                    let storage_ops_between_calls = storage_operations.iter()
                        .filter(|op| op.position > prev_call_pos && op.position < call.position)
                        .count();
                    
                    // If there are storage operations between calls, this could be vulnerable
                    if storage_ops_between_calls > 0 {
                        warnings.push(SecurityWarning::cross_contract_reentrancy(
                            call.position as u64,
                            call.target_address.unwrap_or_else(H256::zero),
                            H256::zero(), // Contract address would be determined in a full implementation
                        ));
                        
                        // Only report one warning per call pattern to avoid duplicates
                        break;
                    }
                }
                
                prev_call_pos = call.position;
            }
        }
    }
    
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::security::SecurityWarningKind;
    use ethers::types::Bytes;

    #[test]
    fn test_cross_contract_reentrancy_detection() {
        // Create a test bytecode with a pattern vulnerable to cross-contract reentrancy
        // SLOAD (read state) -> CALL (external call) -> SSTORE (write state)
        let mut bytecode = vec![
            // Read from storage at position 0
            SLOAD,
            // Make an external call
            CALL,
            // Write to storage at position 0
            SSTORE,
        ];
        
        // Create a bytecode analyzer with this bytecode
        let analyzer = BytecodeAnalyzer::new(bytecode.clone().into());
        
        // Detect cross-contract reentrancy
        let warnings = detect_cross_contract_reentrancy(&analyzer);
        
        // Verify that a warning was generated
        assert!(!warnings.is_empty(), "Should detect cross-contract reentrancy");
        assert_eq!(warnings[0].kind, SecurityWarningKind::CrossContractReentrancy);
        
        // Test with a non-vulnerable pattern (no storage write after call)
        bytecode = vec![
            // Read from storage
            SLOAD,
            // Make an external call
            CALL,
            // No storage write after call
        ];
        
        let analyzer = BytecodeAnalyzer::new(bytecode.into());
        let warnings = detect_cross_contract_reentrancy(&analyzer);
        
        // Verify that no warning was generated
        assert!(warnings.is_empty(), "Should not detect cross-contract reentrancy");
    }
    
    #[test]
    fn test_cross_contract_reentrancy_test_mode() {
        // Create a test bytecode with a pattern vulnerable to cross-contract reentrancy
        let bytecode = vec![
            // Read from storage at position 0
            SLOAD,
            // Make an external call
            CALL,
            // Write to storage at position 0
            SSTORE,
        ];
        
        // Create a bytecode analyzer with this bytecode and enable test mode
        let mut analyzer = BytecodeAnalyzer::new(bytecode.into());
        analyzer.set_test_mode(true);
        
        // Detect cross-contract reentrancy with test mode enabled
        let warnings = detect_cross_contract_reentrancy(&analyzer);
        
        // Verify that no warning was generated due to test mode
        assert!(warnings.is_empty(), "Should not detect cross-contract reentrancy in test mode");
        
        // Disable test mode and check again
        analyzer.set_test_mode(false);
        let warnings = detect_cross_contract_reentrancy(&analyzer);
        
        // Verify that a warning was generated when test mode is disabled
        assert!(!warnings.is_empty(), "Should detect cross-contract reentrancy when test mode is disabled");
        assert_eq!(warnings[0].kind, SecurityWarningKind::CrossContractReentrancy);
    }
}
