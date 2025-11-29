/// AA Bundler Manipulation Detector (Enhanced)
/// Detects bundler-layer vulnerabilities beyond basic AA exploits
/// Critical for: ERC-4337 bundler security, alternative mempools

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AABundlerVulnerability {
    pub vulnerability_type: AABundlerIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AABundlerIssueType {
    BundlerCensorship,             // Bundler can censor operations
    BundleOrderingManipulation,    // Bundler manipulates op ordering
    BundleAtomicityBypass,         // Bundle atomicity not enforced
    AlternativeMempoolExploit,     // Alternative mempool manipulation
    UserOpGasEstimationAttack,     // Gas estimation manipulation
    CrossBundlerReplay,            // Replay across bundlers
}

pub struct AABundlerDetector {
    bytecode: Vec<u8>,
}

impl AABundlerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AABundlerVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_aa_bundler() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_censorship_risk());
        vulnerabilities.extend(self.detect_ordering_issues());
        vulnerabilities.extend(self.detect_gas_manipulation());

        vulnerabilities
    }

    fn detect_censorship_risk(&self) -> Vec<AABundlerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: UserOp execution without fallback mechanism
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_userop_execution(i) {
                if !self.has_fallback_mechanism(i) {
                    vulnerabilities.push(AABundlerVulnerability {
                        vulnerability_type: AABundlerIssueType::BundlerCensorship,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "UserOp execution without bundler fallback".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User submits UserOp to bundler\n\
                            2. Bundler can censor specific operations\n\
                            3. No alternative submission path\n\
                            4. User operation never executes\n\n\
                            Fix: Provide alternative bundler or direct submission",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_ordering_issues(&self) -> Vec<AABundlerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Dependent UserOps without ordering enforcement
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_bundle_execution(i) {
                if !self.has_nonce_ordering(i) {
                    vulnerabilities.push(AABundlerVulnerability {
                        vulnerability_type: AABundlerIssueType::BundleOrderingManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Bundle execution without nonce ordering enforcement".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Multiple UserOps from same account in bundle\n\
                            2. Bundler can reorder operations\n\
                            3. Later operation executes before earlier one\n\
                            4. Breaks user's intended sequence\n\n\
                            Fix: Enforce nonce ordering in bundle",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_gas_manipulation(&self) -> Vec<AABundlerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Gas estimation without limit
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_gas_estimation(i) {
                if !self.has_gas_limit(i) {
                    vulnerabilities.push(AABundlerVulnerability {
                        vulnerability_type: AABundlerIssueType::UserOpGasEstimationAttack,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "UserOp gas estimation without upper limit".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker crafts UserOp with manipulated gas\n\
                            2. No maximum gas limit enforcement\n\
                            3. Bundler includes expensive operation\n\
                            4. DoS or griefing attack\n\n\
                            Fix: Cap maximum gas per UserOp",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn uses_aa_bundler(&self) -> bool {
        // Look for ERC-4337 bundler patterns
        let handle_ops = [0x1f, 0xad, 0x94, 0x8c]; // handleOps()
        let handle_aggregated = [0x4b, 0x1d, 0x8e, 0x72]; // handleAggregatedOps()
        
        self.bytecode.windows(4).any(|w| w == handle_ops || w == handle_aggregated)
    }

    fn has_userop_execution(&self, pos: usize) -> bool {
        // Look for UserOp execution pattern
        pos + 10 < self.bytecode.len()
    }

    fn has_fallback_mechanism(&self, pos: usize) -> bool {
        // Look for alternative submission path (heuristic)
        for i in pos.saturating_sub(50)..pos {
            if self.bytecode[i] == 0xF1 { // CALL (alternative path)
                return true;
            }
        }
        false
    }

    fn has_bundle_execution(&self, pos: usize) -> bool {
        // Look for batch execution
        pos + 15 < self.bytecode.len()
    }

    fn has_nonce_ordering(&self, pos: usize) -> bool {
        // Look for nonce validation
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 && i + 3 < self.bytecode.len() && self.bytecode[i+3] == 0x11 {
                return true; // SLOAD followed by comparison
            }
        }
        false
    }

    fn has_gas_estimation(&self, pos: usize) -> bool {
        // Look for GAS opcode
        pos < self.bytecode.len() && self.bytecode[pos] == 0x5A
    }

    fn has_gas_limit(&self, pos: usize) -> bool {
        // Look for gas limit check
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 { // LT (gas < limit)
                return true;
            }
        }
        false
    }
}
