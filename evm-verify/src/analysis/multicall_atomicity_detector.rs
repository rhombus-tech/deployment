/// Multicall Atomicity Violations Detector
/// Detects vulnerabilities in batch/multicall operations
/// Critical for: Uniswap Universal Router, DEX aggregators, batch executors
///
/// Recent exploits: DEX aggregator partial execution bugs (2023-2024)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticallVulnerability {
    pub vulnerability_type: MulticallIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MulticallIssueType {
    PartialExecutionOnRevert,      // Some calls execute even if batch reverts
    StateInconsistencyBetweenCalls, // State changes between multicall items
    ReentrancyBetweenTargets,      // Reentrancy via multicall targets
    GasGriefingViaFailure,         // Gas griefing through selective failures
    InconsistentErrorHandling,     // Some errors caught, some not
    CrossCallDataLeakage,          // Data from one call affects another
    AtomicityViolation,            // Batch not truly atomic
}

pub struct MulticallAtomicityDetector {
    bytecode: Vec<u8>,
    multicall_selectors: HashSet<[u8; 4]>,
}

impl MulticallAtomicityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut multicall_selectors = HashSet::new();
        
        // Common multicall function selectors
        multicall_selectors.insert([0xac, 0x96, 0x50, 0xd8]); // multicall(bytes[])
        multicall_selectors.insert([0x52, 0xd1, 0x90, 0x2d]); // multicall(uint256,bytes[])
        multicall_selectors.insert([0x5a, 0xe4, 0x01, 0xdc]); // execute(bytes[])
        multicall_selectors.insert([0x1f, 0x0d, 0x38, 0x38]); // aggregate(Call[])
        multicall_selectors.insert([0x82, 0xad, 0x56, 0xcb]); // multicall(bytes)
        
        Self {
            bytecode,
            multicall_selectors,
        }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MulticallVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_multicall_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_partial_execution());
        vulnerabilities.extend(self.detect_reentrancy_between_calls());
        vulnerabilities.extend(self.detect_inconsistent_error_handling());
        vulnerabilities.extend(self.detect_state_inconsistency());

        vulnerabilities
    }

    fn detect_partial_execution(&self) -> Vec<MulticallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: DELEGATECALL/CALL in loop without proper revert handling
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if (self.bytecode[i] == 0xF4 || self.bytecode[i] == 0xF1) && // DELEGATECALL or CALL
               self.is_in_loop_context(i) {
                
                // Check if call failure is handled properly
                let has_proper_revert = self.has_immediate_revert_on_failure(i);
                
                if !has_proper_revert {
                    vulnerabilities.push(MulticallVulnerability {
                        vulnerability_type: MulticallIssueType::PartialExecutionOnRevert,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Multicall may partially execute if mid-batch call fails".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Batch of 5 calls submitted\n\
                            2. Call 3 fails but error not propagated\n\
                            3. Calls 4 and 5 execute despite failure\n\
                            4. State inconsistent with user expectations\n\n\
                            Fix: require(success, 'Call failed'); after each CALL",
                            i
                        ),
                        location: i,
                    });
                }

                // Check for try-catch pattern that swallows errors
                if self.has_error_swallowing_pattern(i) {
                    vulnerabilities.push(MulticallVulnerability {
                        vulnerability_type: MulticallIssueType::InconsistentErrorHandling,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Try-catch swallows errors instead of reverting entire batch".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Critical call in batch fails\n\
                            2. Try-catch catches error and continues\n\
                            3. User expects atomic batch behavior\n\
                            4. Partial execution leaves protocol in bad state\n\n\
                            Fix: Don't use try-catch in atomic operations",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_reentrancy_between_calls(&self) -> Vec<MulticallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: External calls in multicall without reentrancy guard
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_in_multicall_context(i) {
                if (self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xF4) && // CALL or DELEGATECALL
                   !self.has_reentrancy_guard(i) {
                    
                    vulnerabilities.push(MulticallVulnerability {
                        vulnerability_type: MulticallIssueType::ReentrancyBetweenTargets,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.75,
                        description: "Multicall targets can reenter via other batch calls".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Batch: [withdrawA(), depositB()]\n\
                            2. withdrawA() reenters multicall contract\n\
                            3. Calls depositB() before original depositB()\n\
                            4. State inconsistency and fund loss\n\n\
                            Fix: Use reentrancy guard for multicall functions",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_inconsistent_error_handling(&self) -> Vec<MulticallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Some calls checked, others not
        let mut checked_calls = 0;
        let mut unchecked_calls = 0;

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.is_in_multicall_context(i) {
                if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xF4 {
                    if self.has_immediate_revert_on_failure(i) {
                        checked_calls += 1;
                    } else {
                        unchecked_calls += 1;
                    }
                }
            }
        }

        if checked_calls > 0 && unchecked_calls > 0 {
            vulnerabilities.push(MulticallVulnerability {
                vulnerability_type: MulticallIssueType::InconsistentErrorHandling,
                severity: SecuritySeverity::Medium,
                confidence: 0.70,
                description: format!("Inconsistent error handling: {} calls checked, {} unchecked", checked_calls, unchecked_calls),
                exploit_scenario: format!(
                    "Mixed error handling in multicall:\n\
                    1. Some calls revert on failure, others continue\n\
                    2. Unpredictable batch execution behavior\n\
                    3. User cannot rely on atomic guarantees\n\
                    4. May lead to fund loss or state corruption\n\n\
                    Fix: Consistent error handling for all calls"
                ),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn detect_state_inconsistency(&self) -> Vec<MulticallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: SSTORE between CALLs without proper ordering checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_in_multicall_context(i) {
                if self.bytecode[i] == 0xF1 && // CALL
                   i + 20 < self.bytecode.len() {
                    
                    // Check for SSTORE between calls
                    let mut found_sstore = false;
                    let mut found_next_call = false;
                    
                    for j in i+1..i+40 {
                        if j < self.bytecode.len() {
                            if self.bytecode[j] == 0x55 {
                                found_sstore = true;
                            }
                            if self.bytecode[j] == 0xF1 && found_sstore {
                                found_next_call = true;
                                break;
                            }
                        }
                    }
                    
                    if found_sstore && found_next_call {
                        vulnerabilities.push(MulticallVulnerability {
                            vulnerability_type: MulticallIssueType::StateInconsistencyBetweenCalls,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: "State modifications between multicall operations".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. Call A modifies state\n\
                                2. State change visible to Call B\n\
                                3. Call B reads modified state mid-batch\n\
                                4. May break expected atomicity\n\n\
                                Fix: Ensure state changes after all calls or maintain consistency",
                                i
                            ),
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn is_multicall_contract(&self) -> bool {
        for selector in &self.multicall_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        false
    }

    fn is_in_loop_context(&self, pos: usize) -> bool {
        // Look for JUMPDEST before and JUMPI after (loop pattern)
        let has_jumpdest_before = self.bytecode[pos.saturating_sub(20)..pos]
            .iter().any(|&b| b == 0x5B);
        let has_jumpi_after = self.bytecode[pos..pos.saturating_add(30).min(self.bytecode.len())]
            .iter().any(|&b| b == 0x57);
        has_jumpdest_before && has_jumpi_after
    }

    fn is_in_multicall_context(&self, pos: usize) -> bool {
        // Check if near multicall selector
        for i in pos.saturating_sub(100)..pos.saturating_add(100).min(self.bytecode.len()) {
            if i + 4 <= self.bytecode.len() {
                for selector in &self.multicall_selectors {
                    if &self.bytecode[i..i+4] == selector {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_immediate_revert_on_failure(&self, pos: usize) -> bool {
        // Look for ISZERO, PUSH(revert_msg), JUMPI pattern after CALL
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x15 && // ISZERO (check success)
               i + 3 < self.bytecode.len() &&
               self.bytecode[i + 2] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }

    fn has_error_swallowing_pattern(&self, pos: usize) -> bool {
        // Pattern: Call followed by POP (ignore result)
        pos + 1 < self.bytecode.len() && self.bytecode[pos + 1] == 0x50 // POP
    }

    fn has_reentrancy_guard(&self, pos: usize) -> bool {
        // Look for nonReentrant modifier pattern (SLOAD, EQ, REQUIRE)
        for i in pos.saturating_sub(50)..pos {
            if self.bytecode[i] == 0x54 && // SLOAD (reentrancy status)
               i + 5 < self.bytecode.len() &&
               self.bytecode[i + 2] == 0x14 { // EQ (check status)
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchecked_multicall() {
        let bytecode = vec![
            0xac, 0x96, 0x50, 0xd8, // multicall selector
            0x5B, // JUMPDEST (loop)
            0xF1, // CALL
            0x50, // POP (ignore result - dangerous!)
            0x57, // JUMPI (continue loop)
        ];
        
        let detector = MulticallAtomicityDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
