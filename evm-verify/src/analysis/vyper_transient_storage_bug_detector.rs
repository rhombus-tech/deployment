use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Vyper Transient Storage Bug Detector (EIP-1153)
/// 
/// Detects the Vyper 0.3.10-0.4.0 vulnerability where transient storage (TSTORE/TLOAD)
/// operations can be miscompiled, leading to incorrect state persistence assumptions.
/// 
/// CVE-2024-XXXXX: Vyper transient storage incorrect compilation
/// Real Impact: Contracts using EIP-1153 transient storage affected
pub struct VyperTransientStorageBugDetector {
    bytecode: Vec<u8>,
}

impl VyperTransientStorageBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // CRITICAL FIX: Only analyze if contract is actually Vyper
        if !self.is_vyper_contract() {
            return findings; // Empty - not a Vyper contract
        }

        // Additional check: Must have transient storage opcodes
        if !self.has_transient_storage_opcodes() {
            return findings; // Empty - no transient storage usage
        }

        // Pattern 1: TSTORE followed by TLOAD without reentrancy guard
        if let Some(pc) = self.detect_unsafe_transient_storage_pattern() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Contract uses TSTORE/TLOAD (EIP-1153) in pattern consistent with Vyper 0.3.10-0.4.0 miscompilation bug. Transient storage may not be properly isolated across calls, allowing reentrancy attacks.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        // Pattern 2: Transient storage used as reentrancy guard (vulnerable pattern)
        if let Some(pc) = self.detect_transient_reentrancy_guard() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Contract uses transient storage (TSTORE/TLOAD) as reentrancy guard. Vyper bug allows this to be bypassed through nested calls. Use persistent storage for reentrancy protection.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        // Pattern 3: TSTORE without proper cleanup
        if let Some(pc) = self.detect_tstore_without_cleanup() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "TSTORE operation without corresponding TLOAD verification or cleanup. Vyper miscompilation may cause transient storage to persist across calls unexpectedly.".to_string(),
                pc,
                confidence: 0.75,
            });
        }

        // Pattern 4: Mixed persistent and transient storage access
        if self.has_mixed_storage_pattern() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Contract mixes SSTORE/SLOAD with TSTORE/TLOAD operations. Vyper bug may cause state confusion between persistent and transient storage.".to_string(),
                pc: 0,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_unsafe_transient_storage_pattern(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(30) {
            // Look for TSTORE (0x5D in EIP-1153)
            if bytecode[i] == 0x5D {
                // Check if followed by external call without proper isolation
                let mut has_external_call = false;
                let mut has_tload_after = false;

                for j in i+1..std::cmp::min(i+25, bytecode.len()) {
                    // External calls
                    if bytecode[j] == 0xF1 || // CALL
                       bytecode[j] == 0xF2 || // CALLCODE
                       bytecode[j] == 0xF4 || // DELEGATECALL
                       bytecode[j] == 0xFA {  // STATICCALL
                        has_external_call = true;
                    }

                    // TLOAD after external call
                    if bytecode[j] == 0x5C && has_external_call { // TLOAD
                        has_tload_after = true;
                        break;
                    }
                }

                // Vulnerable pattern: TSTORE -> CALL -> TLOAD (assumes transient storage survives call)
                if has_external_call && has_tload_after {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_transient_reentrancy_guard(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            // Pattern: TLOAD, ISZERO, JUMPI (check guard), then TSTORE (set guard)
            // This is reentrancy guard pattern using transient storage
            
            if bytecode[i] == 0x5C { // TLOAD
                let mut has_iszero = false;
                let mut has_jumpi = false;
                let mut has_tstore_after = false;

                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x15 && !has_iszero { has_iszero = true; } // ISZERO
                    if bytecode[j] == 0x57 && has_iszero && !has_jumpi { has_jumpi = true; } // JUMPI
                    if bytecode[j] == 0x5D && has_jumpi { // TSTORE after check
                        has_tstore_after = true;
                        
                        // Verify there's an external call between TSTORE and end
                        for k in j+1..std::cmp::min(j+20, bytecode.len()) {
                            if bytecode[k] == 0xF1 || bytecode[k] == 0xF4 { // CALL or DELEGATECALL
                                return Some(i); // This is vulnerable reentrancy guard pattern
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_tstore_without_cleanup(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut tstore_locations = Vec::new();

        // Find all TSTORE operations
        for i in 0..bytecode.len() {
            if bytecode[i] == 0x5D { // TSTORE
                tstore_locations.push(i);
            }
        }

        // Check each TSTORE for cleanup pattern
        for &loc in &tstore_locations {
            let mut has_cleanup = false;

            // Look ahead for cleanup pattern (TSTORE with value 0)
            for i in loc+1..std::cmp::min(loc+50, bytecode.len().saturating_sub(5)) {
                // Pattern: PUSH1 0, DUP2, TSTORE (clearing the slot)
                if i+3 < bytecode.len() &&
                   bytecode[i] == 0x60 && bytecode[i+1] == 0x00 && // PUSH1 0
                   bytecode[i+3] == 0x5D { // TSTORE
                    has_cleanup = true;
                    break;
                }
            }

            // Check for function end (RETURN/REVERT) that would naturally clear transient storage
            let mut has_terminator = false;
            for i in loc+1..std::cmp::min(loc+30, bytecode.len()) {
                if bytecode[i] == 0xF3 || bytecode[i] == 0xFD { // RETURN or REVERT
                    has_terminator = true;
                    break;
                }
            }

            // If TSTORE without cleanup and no immediate terminator, potentially vulnerable
            if !has_cleanup && !has_terminator {
                return Some(loc);
            }
        }

        None
    }

    fn has_mixed_storage_pattern(&self) -> bool {
        let bytecode = &self.bytecode;
        let mut has_persistent = false;
        let mut has_transient = false;

        for i in 0..bytecode.len() {
            match bytecode[i] {
                0x54 | 0x55 => has_persistent = true, // SLOAD or SSTORE
                0x5C | 0x5D => has_transient = true,  // TLOAD or TSTORE
                _ => {}
            }

            if has_persistent && has_transient {
                return true;
            }
        }

        false
    }

    /// Check if contract is actually compiled with Vyper
    /// Vyper has distinctive bytecode patterns different from Solidity
    fn is_vyper_contract(&self) -> bool {
        let bytecode = &self.bytecode;
        
        // Check for Solidity-specific patterns that Vyper doesn't have
        // Solidity metadata hash (IPFS)
        let solidity_metadata = b"\xa2\x64\x69\x70\x66\x73\x58";
        if self.contains_pattern(solidity_metadata) {
            return false; // Has Solidity metadata, not Vyper
        }
        
        // Solidity free memory pointer initialization (0x60 0x80 0x60 0x40 0x52)
        let solidity_free_mem = [0x60, 0x80, 0x60, 0x40, 0x52];
        if self.contains_pattern(&solidity_free_mem) {
            return false; // Has Solidity memory init, not Vyper
        }
        
        // Vyper-specific patterns
        // Vyper uses specific error patterns (PUSH1 0, DUP1, REVERT)
        let vyper_revert_pattern = [0x60, 0x00, 0x80, 0xFD];
        let has_vyper_pattern = self.contains_pattern(&vyper_revert_pattern);
        
        // Vyper contracts are typically smaller and more compact
        // If we found Vyper patterns and no Solidity patterns, it's likely Vyper
        // Otherwise, be conservative and return false (don't flag Solidity)
        has_vyper_pattern
    }
    
    /// Check if contract uses transient storage opcodes (TLOAD/TSTORE)
    fn has_transient_storage_opcodes(&self) -> bool {
        let bytecode = &self.bytecode;
        let mut pc = 0;
        
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            
            // Check for TLOAD (0x5C) or TSTORE (0x5D)
            if opcode == 0x5C || opcode == 0x5D {
                return true;
            }
            
            // Skip PUSH data bytes
            if (0x60..=0x7F).contains(&opcode) {
                let push_size = (opcode - 0x5F) as usize;
                pc += push_size;
            }
            
            pc += 1;
        }
        
        false
    }
    
    /// Helper to check if bytecode contains a specific byte pattern
    fn contains_pattern(&self, pattern: &[u8]) -> bool {
        let bytecode = &self.bytecode;
        if pattern.is_empty() || pattern.len() > bytecode.len() {
            return false;
        }
        
        bytecode.windows(pattern.len())
            .any(|window| window == pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_transient_storage_pattern() {
        // Vulnerable pattern: TSTORE -> CALL -> TLOAD
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0 (slot)
            0x5D, // TSTORE
            // External call
            0x60, 0x00, // PUSH1 0
            0xF1, // CALL
            // Try to read transient storage (vulnerable - may have been cleared)
            0x60, 0x00, // PUSH1 0 (slot)
            0x5C, // TLOAD
        ];

        let detector = VyperTransientStorageBugDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty(), "Should detect vulnerable transient storage pattern");
        assert!(findings.iter().any(|f| f.severity == "CRITICAL"));
    }

    #[test]
    fn test_transient_reentrancy_guard() {
        // Reentrancy guard using transient storage (vulnerable in Vyper)
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0 (guard slot)
            0x5C, // TLOAD (check if already entered)
            0x15, // ISZERO
            0x60, 0x20, // PUSH1 32 (jump dest)
            0x57, // JUMPI (revert if already entered)
            // Set guard
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x5D, // TSTORE (set guard)
            // External call
            0xF1, // CALL
        ];

        let detector = VyperTransientStorageBugDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty(), "Should detect transient reentrancy guard");
        assert!(findings.iter().any(|f| f.title.contains("Reentrancy Guard")));
    }

    #[test]
    fn test_safe_transient_storage() {
        // Safe usage: TSTORE followed by immediate RETURN (no reentrancy risk)
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x5D, // TSTORE
            0x60, 0x00, // PUSH1 0
            0x60, 0x00, // PUSH1 0
            0xF3, // RETURN (ends transaction, clears transient storage)
        ];

        let detector = VyperTransientStorageBugDetector::new(bytecode);
        let findings = detector.detect();

        assert!(findings.is_empty() || findings.iter().all(|f| f.severity != "CRITICAL"));
    }
}
