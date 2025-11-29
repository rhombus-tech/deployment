/// Time-Bandit Attack Detector
/// Detects consensus-level MEV via block reorganization
/// Critical for: High-value transactions, consensus security

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBanditVulnerability {
    pub vulnerability_type: TimeBanditIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeBanditIssueType {
    BlockReorgVulnerable,          // Vulnerable to block reorg
    UncleBlockManipulation,        // Uncle block exploitation
    ConsensusLevelMEV,             // Consensus-level MEV extraction
    FinalityAssumptionWeak,        // Weak finality assumptions
    ReorgIncentivePresent,         // Economic reorg incentive
}

pub struct TimeBanditDetector {
    bytecode: Vec<u8>,
}

impl TimeBanditDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_reorg_vulnerability());
        vulnerabilities.extend(self.detect_finality_issues());

        vulnerabilities
    }

    fn detect_reorg_vulnerability(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: High-value operation without finality wait
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_high_value_operation(i) {
                if !self.has_finality_delay(i) {
                    vulnerabilities.push(TimeBanditVulnerability {
                        vulnerability_type: TimeBanditIssueType::BlockReorgVulnerable,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "High-value operation without reorg protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Large value transaction confirmed\n\
                            2. No wait for finality (32+ blocks)\n\
                            3. Validator reorgs chain for MEV\n\
                            4. Transaction reversed\n\
                            5. Double-spend or state manipulation\n\n\
                            Fix: Wait for finality before critical actions",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_finality_issues(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Immediate state change after external call
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 && // CALL
               i + 5 < self.bytecode.len() &&
               self.bytecode[i+3] == 0x55 { // Immediate SSTORE
                
                vulnerabilities.push(TimeBanditVulnerability {
                    vulnerability_type: TimeBanditIssueType::FinalityAssumptionWeak,
                    severity: SecuritySeverity::Low,
                    confidence: 0.60,
                    description: "State change immediately after external call".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. External call triggers state change\n\
                        2. No finality buffer\n\
                        3. Chain reorg possible\n\
                        4. State becomes inconsistent\n\n\
                        Note: Low probability but high impact if exploited",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn has_high_value_operation(&self, pos: usize) -> bool {
        // Heuristic: Look for CALL with large value (high byte pushes)
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xF1 { // CALL
                return true;
            }
        }
        false
    }

    fn has_finality_delay(&self, pos: usize) -> bool {
        // Look for NUMBER comparison (block confirmation check)
        for i in pos.saturating_sub(50)..pos {
            if self.bytecode[i] == 0x43 { // NUMBER
                return true;
            }
        }
        false
    }
}
