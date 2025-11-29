/// Vyper Reentrancy Guard Bug Detector
/// Detects the critical Vyper compiler bug (versions 0.2.15-0.3.0) where
/// the @nonreentrant decorator was broken, allowing reentrancy attacks
///
/// Famous exploit: Curve Finance pools were vulnerable (reported but not exploited)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VyperReentrancyBugVulnerability {
    pub vulnerability_type: VyperBugType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub affected_versions: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VyperBugType {
    BrokenNonReentrant,        // @nonreentrant decorator doesn't work
    MissingReentrancyCheck,    // Expected guard not present
    VyperVersionVulnerable,    // Compiled with vulnerable Vyper version
}

pub struct VyperReentrancyBugDetector {
    bytecode: Vec<u8>,
}

impl VyperReentrancyBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VyperReentrancyBugVulnerability> {
        let mut vulnerabilities = Vec::new();

        // First check if this is Vyper bytecode
        if !self.is_vyper_contract() {
            return vulnerabilities;
        }

        // Pattern 1: Detect vulnerable Vyper version signature
        if self.has_vulnerable_vyper_version() {
            vulnerabilities.extend(self.detect_broken_nonreentrant());
        }

        // Pattern 2: External calls without proper reentrancy guard
        vulnerabilities.extend(self.detect_missing_reentrancy_protection());

        vulnerabilities
    }

    /// Check if bytecode is from Vyper compiler
    fn is_vyper_contract(&self) -> bool {
        // Vyper has distinctive patterns:
        // 1. Specific function selector layout
        // 2. Unique storage access patterns
        // 3. Different from Solidity's function dispatcher
        
        // Look for Vyper-specific patterns
        let has_vyper_dispatcher = self.has_vyper_function_dispatcher();
        let has_vyper_storage = self.has_vyper_storage_pattern();
        
        has_vyper_dispatcher || has_vyper_storage
    }

    fn has_vyper_function_dispatcher(&self) -> bool {
        // Vyper uses a specific function dispatch pattern
        // Look for: CALLDATASIZE check followed by specific jump table
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x36 && // CALLDATASIZE
               self.bytecode[i + 1] == 0x60 && // PUSH1
               self.bytecode[i + 2] == 0x03 { // 3 (checking calldata size >= 4)
                return true;
            }
        }
        
        false
    }

    fn has_vyper_storage_pattern(&self) -> bool {
        // Vyper uses specific storage layout patterns
        // Look for packed storage access (Vyper packs more aggressively than Solidity)
        
        let mut storage_accesses = 0;
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x54 { // SLOAD
                storage_accesses += 1;
            }
        }
        
        // Vyper tends to have many storage accesses due to its design
        storage_accesses > 10
    }

    /// Detect vulnerable Vyper versions (0.2.15 - 0.3.0)
    fn has_vulnerable_vyper_version(&self) -> bool {
        // Vyper versions embed metadata differently than Solidity
        // Look for version-specific bytecode patterns
        
        // The vulnerable versions had a specific bug in how they implemented
        // the reentrancy lock using storage slots
        
        // Look for buggy reentrancy guard pattern:
        // It would check the lock but not properly prevent reentrancy
        self.has_buggy_reentrancy_guard_pattern()
    }

    fn has_buggy_reentrancy_guard_pattern(&self) -> bool {
        // The bug: Vyper's @nonreentrant would generate code that:
        // 1. Checks if locked
        // 2. But the check could be bypassed due to storage slot confusion
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for: SLOAD, DUP, ISZERO, then JUMPI
            // This is the broken check pattern
            if self.bytecode[i] == 0x54 && // SLOAD
               self.bytecode[i + 1] == 0x80 && // DUP1
               self.bytecode.get(i + 2) == Some(&0x15) && // ISZERO
               self.bytecode.get(i + 3) == Some(&0x57) { // JUMPI
                
                // Check if there's an external call after without proper lock set
                if self.has_external_call_after(i + 4, 100) {
                    return true;
                }
            }
        }
        
        false
    }

    fn detect_broken_nonreentrant(&self) -> Vec<VyperReentrancyBugVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.push(VyperReentrancyBugVulnerability {
            vulnerability_type: VyperBugType::BrokenNonReentrant,
            severity: SecuritySeverity::Critical,
            confidence: 0.90,
            description:
                "Contract appears to be compiled with vulnerable Vyper version (0.2.15-0.3.0). \
                The @nonreentrant decorator is broken in these versions, providing no actual \
                reentrancy protection.".to_string(),
            affected_versions: "Vyper 0.2.15, 0.2.16, 0.3.0".to_string(),
            exploit_scenario:
                "Critical Vyper Bug (CVE-2023-XXXXX):\n\
                 1. Contract uses @nonreentrant decorator\n\
                 2. Developer believes function is protected\n\
                 3. But the guard is broken in Vyper 0.2.15-0.3.0\n\
                 4. Attacker can reenter despite the decorator\n\
                 5. Classic reentrancy attack succeeds\n\n\
                 Real Impact: Curve Finance pools were vulnerable\n\
                 Mitigation: Upgrade to Vyper 0.3.1+ immediately".to_string(),
            location: 0,
        });

        vulnerabilities
    }

    fn detect_missing_reentrancy_protection(&self) -> Vec<VyperReentrancyBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        let external_calls = self.find_external_calls();

        for call_pc in external_calls {
            // Check if there's a reentrancy guard before this call
            let has_guard = self.has_reentrancy_guard_before(call_pc, 100);
            let has_state_change_after = self.has_state_change_after(call_pc, 50);

            if !has_guard && has_state_change_after {
                vulnerabilities.push(VyperReentrancyBugVulnerability {
                    vulnerability_type: VyperBugType::MissingReentrancyCheck,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: format!(
                        "External call at PC {} with state changes after, but no reentrancy guard. \
                        If this is Vyper 0.2.15-0.3.0, even @nonreentrant won't protect you.",
                        call_pc
                    ),
                    affected_versions: "All Vyper versions if missing @nonreentrant".to_string(),
                    exploit_scenario:
                        "Classic reentrancy in Vyper:\n\
                         1. Function makes external call\n\
                         2. State updated after call\n\
                         3. No @nonreentrant decorator OR using broken version\n\
                         4. Attacker reenters before state update\n\
                         5. Exploits stale state".to_string(),
                    location: call_pc,
                });
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn find_external_calls(&self) -> Vec<usize> {
        let mut calls = Vec::new();
        
        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0xF1 | 0xF2 | 0xF4 => calls.push(i), // CALL, CALLCODE, DELEGATECALL
                _ => {}
            }
        }
        
        calls
    }

    fn has_external_call_after(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        self.bytecode[start..end].iter()
            .any(|&op| matches!(op, 0xF1 | 0xF2 | 0xF4))
    }

    fn has_reentrancy_guard_before(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        
        // Look for reentrancy lock pattern: SLOAD, check, SSTORE
        for i in start..pc {
            if i + 5 < pc {
                if self.bytecode[i] == 0x54 && // SLOAD
                   self.bytecode[i + 1] == 0x15 && // ISZERO or similar check
                   self.bytecode.get(i + 4) == Some(&0x55) { // SSTORE later
                    return true;
                }
            }
        }
        
        false
    }

    fn has_state_change_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        self.bytecode[pc..end].contains(&0x55) // SSTORE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vyper_pattern_detection() {
        // Simplified Vyper pattern
        let bytecode = vec![
            0x36, // CALLDATASIZE (Vyper signature)
            0x60, 0x03, // PUSH1 3
            0x54, // SLOAD (reentrancy check)
            0x80, // DUP1
            0x15, // ISZERO
            0x57, // JUMPI
            0xF1, // CALL (external call)
            0x55, // SSTORE (state change after)
        ];
        
        let detector = VyperReentrancyBugDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect Vyper reentrancy issues");
    }
}
