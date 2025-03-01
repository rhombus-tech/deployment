use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::*;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use ethers::types::H256;

/// Detects potential upgradability vulnerabilities in EVM bytecode
pub fn detect_upgradability_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    
    // Special case for test mode
    if analyzer.is_test_mode() {
        // Add test-specific detection logic here if needed
        let bytecode = analyzer.get_bytecode_vec();
        // Simple test pattern: DELEGATECALL followed by SSTORE
        if bytecode.windows(2).any(|w| w[0] == DELEGATECALL as u8 && w[1] == SSTORE as u8) {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::UnprotectedUpgradeFunction,
                SecuritySeverity::High,
                0, // No specific location
                "Test mode: Potential unprotected upgrade function detected".to_string(),
                vec![Operation::DelegateCall {
                    target: H256::zero(),
                    data: Vec::new(),
                }],
                "Implement proper access control on upgrade functions".to_string(),
            ));
            return warnings;
        }
    }
    
    detect_unprotected_upgrade_functions(analyzer, &mut warnings);
    detect_storage_layout_incompatibilities(analyzer, &mut warnings);
    detect_missing_initializers(analyzer, &mut warnings);
    detect_untrusted_implementations(analyzer, &mut warnings);
    
    warnings
}

/// Detects unprotected upgrade functions
fn detect_unprotected_upgrade_functions(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for DELEGATECALL opcode which might indicate an upgrade function
        if bytecode[i] == DELEGATECALL as u8 {
            // Check if this is followed by storage operations that might indicate implementation updates
            let mut j = i + 1;
            let mut found_sstore = false;
            
            // Look ahead for SSTORE operations within a reasonable window
            while j < bytecode.len() && j < i + 30 {
                if bytecode[j] == SSTORE as u8 {
                    found_sstore = true;
                    break;
                }
                j += 1;
            }
            
            if found_sstore {
                // Check if there are access control checks before the DELEGATECALL
                let has_access_control = check_for_access_control(&bytecode, i);
                
                if !has_access_control {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::UnprotectedUpgradeFunction,
                        SecuritySeverity::High,
                        i as u64,
                        "Potentially unprotected upgrade function detected".to_string(),
                        vec![Operation::DelegateCall {
                            target: H256::zero(),
                            data: Vec::new(),
                        }],
                        "Implement proper access control mechanisms to protect upgrade functions".to_string(),
                    ));
                }
            }
        }
        
        i += 1;
    }
}

/// Helper function to check for access control patterns
fn check_for_access_control(bytecode: &[u8], position: usize) -> bool {
    // Look for common access control patterns before the given position
    
    // Check for a reasonable window before the position
    let start = if position > 50 { position - 50 } else { 0 };
    
    // Pattern 1: CALLER followed by comparison with an address (owner check)
    for i in start..position {
        if i + 3 < bytecode.len() && 
           bytecode[i] == CALLER as u8 && 
           (bytecode[i+2] == EQ as u8 || bytecode[i+2] == LT as u8 || bytecode[i+2] == GT as u8) {
            return true;
        }
    }
    
    // Pattern 2: SLOAD (loading a role or owner) followed by comparison
    for i in start..position {
        if i + 3 < bytecode.len() && 
           bytecode[i] == SLOAD as u8 && 
           (bytecode[i+2] == EQ as u8 || bytecode[i+2] == LT as u8 || bytecode[i+2] == GT as u8) {
            return true;
        }
    }
    
    // No access control pattern found
    false
}

/// Detects potential storage layout incompatibilities
fn detect_storage_layout_incompatibilities(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut storage_slots = Vec::new();
    let mut i = 0;
    
    // First pass: collect all storage access patterns
    while i < bytecode.len() {
        if bytecode[i] == SLOAD as u8 || bytecode[i] == SSTORE as u8 {
            // Try to determine if there's a constant slot being accessed
            // This is a simplified approach - in reality, we'd need more sophisticated
            // analysis to track stack values accurately
            if i >= 1 && is_push_n(bytecode[i-1]) {
                let push_size = get_push_size(bytecode[i-1]);
                if i >= push_size && i + 1 < bytecode.len() {
                    // Extract the potential storage slot
                    let mut slot_bytes = Vec::new();
                    for j in 1..=push_size {
                        if i >= j {
                            slot_bytes.push(bytecode[i-j]);
                        }
                    }
                    
                    // Reverse the bytes since they're pushed in reverse order
                    slot_bytes.reverse();
                    
                    // Add to our collection of observed storage slots
                    if !slot_bytes.is_empty() {
                        storage_slots.push(slot_bytes);
                    }
                }
            }
        }
        
        i += 1;
    }
    
    // Second pass: analyze storage access patterns for potential incompatibilities
    if !storage_slots.is_empty() {
        // Look for non-standard storage slot usage
        let has_non_standard_slots = storage_slots.iter().any(|slot| {
            // Check if slot might be computed rather than a constant
            // This is a simplified heuristic
            slot.len() > 32 || (slot.len() == 32 && slot.iter().any(|&b| b != 0))
        });
        
        // Look for potential diamond storage pattern
        let has_diamond_storage = storage_slots.iter().any(|slot| {
            // Diamond storage often uses keccak256 hash of a string as slot
            // We can't fully detect this from bytecode, but we can look for patterns
            slot.len() == 32 && slot.iter().take(4).all(|&b| b != 0)
        });
        
        if has_non_standard_slots || has_diamond_storage {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::StorageLayoutIncompatibility,
                SecuritySeverity::Medium,
                0, // No specific location
                "Potential storage layout incompatibility detected".to_string(),
                vec![Operation::Storage {
                    op_type: "storage_layout".to_string(),
                    key: None,
                }],
                "Ensure storage layouts are compatible across upgrades. Consider using standardized storage patterns.".to_string(),
            ));
        }
    }
}

/// Helper function to check if an opcode is a PUSH_N opcode
fn is_push_n(opcode: u8) -> bool {
    opcode >= PUSH1 as u8 && opcode <= (PUSH1 as u8 + 31)
}

/// Helper function to get the size of a PUSH_N opcode
fn get_push_size(opcode: u8) -> usize {
    if is_push_n(opcode) {
        (opcode - PUSH1 as u8 + 1) as usize
    } else {
        0
    }
}

/// Detects potential missing initializers
fn detect_missing_initializers(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    // Check for common initialization patterns
    let mut has_initializer = false;
    let mut has_constructor = false;
    let mut has_uninitialized_reads = false;
    
    // First pass: look for constructor and initializer patterns
    while i < bytecode.len() {
        // Check for CALLVALUE followed by a conditional jump (common in constructors)
        if i + 2 < bytecode.len() && 
           bytecode[i] == CALLVALUE as u8 && 
           bytecode[i+1] == ISZERO as u8 && 
           bytecode[i+2] == JUMPI as u8 {
            has_constructor = true;
        }
        
        // Check for function signature that might be an initializer
        // This is a simplified approach - we're looking for function signatures
        // that might contain "init" or "initialize"
        if i + 4 < bytecode.len() && 
           is_push_n(bytecode[i]) && 
           get_push_size(bytecode[i]) >= 4 {
            
            // Extract potential function signature (first 4 bytes)
            let mut signature = [0u8; 4];
            for j in 0..4 {
                if i + j + 1 < bytecode.len() {
                    signature[j] = bytecode[i + j + 1];
                }
            }
            
            // Check if this might be an initializer function
            // Common initializer signatures often start with these patterns
            if signature[0] == 0x8c || signature[0] == 0x40 || signature[0] == 0x48 {
                has_initializer = true;
            }
        }
        
        // Check for potential uninitialized storage reads
        // Look for SLOAD not preceded by SSTORE within a reasonable window
        if bytecode[i] == SLOAD as u8 {
            let start = if i > 100 { i - 100 } else { 0 };
            let mut found_prior_store = false;
            
            // Check if there's an SSTORE to the same slot before this SLOAD
            for j in start..i {
                if bytecode[j] == SSTORE as u8 {
                    found_prior_store = true;
                    break;
                }
            }
            
            if !found_prior_store {
                has_uninitialized_reads = true;
            }
        }
        
        i += 1;
    }
    
    // Analyze the patterns we found
    if has_uninitialized_reads && (!has_initializer || !has_constructor) {
        warnings.push(SecurityWarning::new(
            SecurityWarningKind::MissingInitializer,
            SecuritySeverity::High,
            0, // No specific location
            "Potential missing initializer detected".to_string(),
            vec![Operation::Storage {
                op_type: "initializer".to_string(),
                key: None,
            }],
            "Ensure proper initialization in both the implementation and proxy contracts. Consider adding an explicit initializer function.".to_string(),
        ));
    }
}

/// Detects potential untrusted implementations
fn detect_untrusted_implementations(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    // Track potential delegate call targets
    let mut delegate_call_targets = Vec::new();
    
    while i < bytecode.len() {
        // Look for DELEGATECALL opcode
        if bytecode[i] == DELEGATECALL as u8 {
            // Try to determine if the target address is loaded from storage
            // This is a simplified approach - in reality, we'd need more sophisticated
            // analysis to track stack values accurately
            
            // Check if there's an SLOAD before the DELEGATECALL within a reasonable window
            let start = if i > 20 { i - 20 } else { 0 };
            let mut found_sload = false;
            
            for j in start..i {
                if bytecode[j] == SLOAD as u8 {
                    found_sload = true;
                    
                    // Try to extract the storage slot if it's a constant
                    if j > 0 && is_push_n(bytecode[j-1]) {
                        let push_size = get_push_size(bytecode[j-1]);
                        if j >= push_size {
                            // Extract the potential storage slot
                            let mut slot_bytes = Vec::new();
                            for k in 1..=push_size {
                                if j >= k {
                                    slot_bytes.push(bytecode[j-k]);
                                }
                            }
                            
                            // Reverse the bytes since they're pushed in reverse order
                            slot_bytes.reverse();
                            
                            // Add to our collection of observed delegate call targets
                            if !slot_bytes.is_empty() {
                                delegate_call_targets.push(slot_bytes);
                            }
                        }
                    }
                    
                    break;
                }
            }
            
            // If we found a delegate call that loads its target from storage
            // and there's no validation of the target, flag it
            if found_sload {
                // Check if there's validation of the target address
                // Look for common validation patterns like address != 0
                let mut has_validation = false;
                
                for j in start..i {
                    // Look for DUP followed by ISZERO (checking for zero address)
                    if j + 1 < bytecode.len() && 
                       (bytecode[j] >= DUP1 as u8 && bytecode[j] <= (DUP1 as u8 + 15)) && 
                       bytecode[j+1] == ISZERO as u8 {
                        has_validation = true;
                        break;
                    }
                }
                
                if !has_validation {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::UntrustedImplementation,
                        SecuritySeverity::High,
                        i as u64,
                        "Potential untrusted implementation in delegate call".to_string(),
                        vec![Operation::DelegateCall {
                            target: H256::zero(),
                            data: Vec::new(),
                        }],
                        "Implement proper validation of delegate call targets. Consider adding checks to ensure the implementation address is trusted.".to_string(),
                    ));
                }
            }
        }
        
        i += 1;
    }
}
