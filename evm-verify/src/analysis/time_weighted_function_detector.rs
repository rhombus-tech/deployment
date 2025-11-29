/// Time-Weighted Function (TWF) Exploit Detector
/// Beyond TWAP - general time-weighted mechanism vulnerabilities
/// Critical for: Staking rewards, vesting, time-locked mechanisms

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TWFVulnerability {
    pub vulnerability_type: TWFIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TWFIssueType {
    TimeWeightedRewardManipulation, // Manipulate time-weighted rewards
    EpochBoundaryExploitation,     // Exploit epoch transitions
    TimeLockBypassViaTimestamp,    // Bypass time-lock using timestamp
    DurationDiscountExploit,       // Exploit duration-based discounts
    CompoundingFrequencyManipulation, // Manipulate compounding frequency
}

pub struct TimeWeightedFunctionDetector {
    bytecode: Vec<u8>,
}

impl TimeWeightedFunctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TWFVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_time_weighted_reward_issues());
        vulnerabilities.extend(self.detect_epoch_boundary_exploits());
        vulnerabilities.extend(self.detect_duration_based_exploits());

        vulnerabilities
    }

    fn detect_time_weighted_reward_issues(&self) -> Vec<TWFVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: TIMESTAMP used in reward calculation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 10 < self.bytecode.len() {
                // Check if used in multiplication (reward calculation)
                for j in i..i+10 {
                    if self.bytecode[j] == 0x02 { // MUL (time * rate)
                        if !self.has_last_update_tracking(i) {
                            vulnerabilities.push(TWFVulnerability {
                                vulnerability_type: TWFIssueType::TimeWeightedRewardManipulation,
                                severity: SecuritySeverity::High,
                                confidence: 0.80,
                                description: "Time-weighted rewards without lastUpdate tracking".to_string(),
                                exploit_scenario: format!(
                                    "Exploit at position {}:\n\
                                    1. User stakes, waits, claims rewards\n\
                                    2. No lastUpdateTimestamp stored properly\n\
                                    3. User can claim same time period twice\n\
                                    4. Double-counting of rewards\n\
                                    5. Reward pool drained\n\n\
                                    Fix: Store and validate lastUpdateTime per user",
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

        vulnerabilities
    }

    fn detect_epoch_boundary_exploits(&self) -> Vec<TWFVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Epoch calculation via MOD
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 5 < self.bytecode.len() &&
               self.bytecode[i + 3] == 0x06 { // MOD (timestamp % epochLength)
                
                if !self.has_boundary_protection(i) {
                    vulnerabilities.push(TWFVulnerability {
                        vulnerability_type: TWFIssueType::EpochBoundaryExploitation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: "Epoch boundary without atomicity protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Epoch transitions at timestamp T\n\
                            2. User submits tx just before T\n\
                            3. User benefits from both epochs\n\
                            4. Double-counting at boundary\n\n\
                            Fix: Add grace period or atomic epoch transitions",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_duration_based_exploits(&self) -> Vec<TWFVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Duration-based discount (SUB for duration, MUL for discount)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 10 < self.bytecode.len() {
                // Look for SUB (end - start) then MUL/DIV (discount calculation)
                let has_sub = self.bytecode[i..i+10].iter().any(|&b| b == 0x03);
                let has_mul_div = self.bytecode[i..i+10].iter().any(|&b| b == 0x02 || b == 0x04);
                
                if has_sub && has_mul_div && !self.has_duration_bounds_check(i) {
                    vulnerabilities.push(TWFVulnerability {
                        vulnerability_type: TWFIssueType::DurationDiscountExploit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Duration-based calculation without bounds checking".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Longer duration = better discount/rate\n\
                            2. No maximum duration check\n\
                            3. User commits to extremely long duration\n\
                            4. Gets outsized discount\n\
                            5. Exits early with profit\n\n\
                            Fix: Cap maximum duration benefit",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_last_update_tracking(&self, pos: usize) -> bool {
        // Look for SSTORE (storing lastUpdate)
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x55 { // SSTORE
                return true;
            }
        }
        false
    }

    fn has_boundary_protection(&self, pos: usize) -> bool {
        // Look for additional checks around epoch transition
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x14 { // EQ (checking exact boundary)
                return true;
            }
        }
        false
    }

    fn has_duration_bounds_check(&self, pos: usize) -> bool {
        // Look for comparison (max duration check)
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }
}
