/// PBS (Proposer-Builder Separation) Manipulation Detector
/// Detects vulnerabilities in post-merge MEV-Boost/PBS architecture
/// Critical for: Ethereum post-merge, time-sensitive transactions, MEV protection
///
/// Recent context: MEV-Boost relay centralization, builder censorship (2024)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PBSVulnerability {
    pub vulnerability_type: PBSIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PBSIssueType {
    BuilderCensorshipVulnerable,   // Time-sensitive tx can be censored by builders
    RelayTrustAssumption,          // Relies on honest MEV-Boost relay
    PrivateOrderflowLeakage,       // Private orderflow exposed to builders
    BlockProposerManipulation,     // Proposer can manipulate block ordering
    TimeSensitiveWithoutProtection, // Time-critical tx without PBS protection
    MEVBoostBypass,                // MEV extraction without going through relay
    ValidatorCollusion,            // Multi-validator collusion vulnerability
}

pub struct PBSManipulationDetector {
    bytecode: Vec<u8>,
    time_sensitive_selectors: HashSet<[u8; 4]>,
}

impl PBSManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut time_sensitive_selectors = HashSet::new();
        
        // Time-sensitive operations
        time_sensitive_selectors.insert([0x3c, 0xcd, 0xfd, 0x4e]); // liquidate()
        time_sensitive_selectors.insert([0xfc, 0x0c, 0x54, 0x6a]); // swap() with deadline
        time_sensitive_selectors.insert([0x79, 0x1a, 0xc9, 0x47]); // execute() time-sensitive
        time_sensitive_selectors.insert([0x58, 0x5a, 0x9d, 0x1c]); // claim() rewards
        
        Self {
            bytecode,
            time_sensitive_selectors,
        }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PBSVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_builder_censorship_risk());
        vulnerabilities.extend(self.detect_timestamp_manipulation_risk());
        vulnerabilities.extend(self.detect_mev_exposure());

        vulnerabilities
    }

    fn detect_builder_censorship_risk(&self) -> Vec<PBSVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Time-sensitive operations without deadline or censorship resistance
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 <= self.bytecode.len() {
                for selector in &self.time_sensitive_selectors {
                    if &self.bytecode[i..i+4] == selector {
                        // Check if there's a deadline parameter
                        let has_deadline = self.has_deadline_check(i);
                        
                        if !has_deadline {
                            vulnerabilities.push(PBSVulnerability {
                                vulnerability_type: PBSIssueType::BuilderCensorshipVulnerable,
                                severity: SecuritySeverity::High,
                                confidence: 0.80,
                                description: "Time-sensitive operation vulnerable to builder censorship".to_string(),
                                exploit_scenario: format!(
                                    "Exploit at position {}:\n\
                                    1. User submits time-sensitive transaction (liquidation/claim)\n\
                                    2. Builder sees tx in mempool\n\
                                    3. Builder delays inclusion for profit\n\
                                    4. Or censors tx entirely if profitable\n\
                                    5. User loses opportunity (failed liquidation, missed claim)\n\n\
                                    Fix: Add deadline parameter and use Flashbots Protect/private RPC",
                                    i
                                ),
                                location: i,
                            });
                        }

                        // Check for block.number dependency (vulnerable to PBS)
                        if self.has_block_number_dependency(i) {
                            vulnerabilities.push(PBSVulnerability {
                                vulnerability_type: PBSIssueType::BlockProposerManipulation,
                                severity: SecuritySeverity::Medium,
                                confidence: 0.75,
                                description: "Operation depends on block.number (manipulable by proposer)".to_string(),
                                exploit_scenario: format!(
                                    "Exploit at position {}:\n\
                                    1. Contract relies on specific block.number\n\
                                    2. Proposer can choose which txs to include\n\
                                    3. Proposer excludes/includes to hit target block\n\
                                    4. Manipulates outcome for profit\n\n\
                                    Fix: Use block.timestamp with longer windows",
                                    i
                                ),
                                location: i,
                            });
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_timestamp_manipulation_risk(&self) -> Vec<PBSVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: TIMESTAMP used in critical logic (post-merge implications)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used for important decisions
                if i + 10 < self.bytecode.len() {
                    // Look for comparison (LT, GT, EQ)
                    for j in i..i+10 {
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 || self.bytecode[j] == 0x14 {
                            // Check if this is in time-sensitive context
                            if self.is_in_critical_function(i) {
                                vulnerabilities.push(PBSVulnerability {
                                    vulnerability_type: PBSIssueType::TimeSensitiveWithoutProtection,
                                    severity: SecuritySeverity::Medium,
                                    confidence: 0.70,
                                    description: "Timestamp-based logic in critical function (PBS timing manipulation)".to_string(),
                                    exploit_scenario: format!(
                                        "Exploit at position {}:\n\
                                        1. Contract uses block.timestamp for deadlines\n\
                                        2. Builders can choose block timestamp (±15 seconds)\n\
                                        3. Builder manipulates timestamp to pass/fail checks\n\
                                        4. Extracts MEV via timing control\n\n\
                                        Fix: Use longer time windows (>1 minute) to mitigate",
                                        i
                                    ),
                                    location: i,
                                });
                            }
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_mev_exposure(&self) -> Vec<PBSVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Swap/trade operations without slippage or private submission
        for i in 0..self.bytecode.len().saturating_sub(40) {
            let swap_selector = [0x38, 0xed, 0x17, 0x39]; // swapExactTokensForTokens
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &swap_selector {
                // Check if there's Flashbots/private RPC integration
                let has_mev_protection = self.has_mev_protection_pattern(i);
                
                if !has_mev_protection {
                    vulnerabilities.push(PBSVulnerability {
                        vulnerability_type: PBSIssueType::PrivateOrderflowLeakage,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Swap exposed to public mempool without MEV protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User swap visible in public mempool\n\
                            2. Builder/searcher sees pending swap\n\
                            3. Frontrun: Buy before user\n\
                            4. User swap executes at worse price\n\
                            5. Backrun: Sell after user\n\
                            6. Searcher profits, user loses\n\n\
                            Fix: Use Flashbots Protect or CoW Protocol",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_deadline_check(&self, pos: usize) -> bool {
        // Look for TIMESTAMP comparison nearby (deadline pattern)
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 3 < self.bytecode.len() &&
               (self.bytecode[i+2] == 0x10 || self.bytecode[i+2] == 0x11) { // LT or GT
                return true;
            }
        }
        false
    }

    fn has_block_number_dependency(&self, pos: usize) -> bool {
        // Look for NUMBER opcode usage
        for i in pos.saturating_sub(30)..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x43 { // NUMBER
                return true;
            }
        }
        false
    }

    fn is_in_critical_function(&self, pos: usize) -> bool {
        // Check if near time-sensitive selectors
        for i in pos.saturating_sub(100)..pos {
            if i + 4 <= self.bytecode.len() {
                for selector in &self.time_sensitive_selectors {
                    if &self.bytecode[i..i+4] == selector {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_mev_protection_pattern(&self, _pos: usize) -> bool {
        // Look for Flashbots-style signatures or private submission patterns
        // This is a heuristic - actual detection would need more context
        // For now, we conservatively return false to flag potential issues
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_censorship_vulnerable_liquidation() {
        let bytecode = vec![
            0x3c, 0xcd, 0xfd, 0x4e, // liquidate() selector
            // No deadline check
            0xF1, // CALL
        ];
        
        let detector = PBSManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PBSIssueType::BuilderCensorshipVulnerable)));
    }

    #[test]
    fn test_timestamp_manipulation() {
        let bytecode = vec![
            0x3c, 0xcd, 0xfd, 0x4e, // liquidate()
            0x42, // TIMESTAMP
            0x60, 0x01, // PUSH1 threshold
            0x10, // LT (comparison)
        ];
        
        let detector = PBSManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
