/// Reward Distribution Bug Detector
/// Detects cumulative reward errors, distribution timing issues, reward calculation overflow

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RewardVulnerabilityType {
    CumulativeRewardError,
    DistributionTimingIssue,
    RewardOverflow,
    RoundingError,
    RewardManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity { Critical, High, Medium, Low }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardVulnerability {
    pub vulnerability_type: RewardVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct RewardDistributionDetector {
    bytecode: Vec<u8>,
}

impl RewardDistributionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_cumulative_errors());
        vulnerabilities.extend(self.detect_overflow_risks());
        vulnerabilities.extend(self.detect_rounding_errors());
        vulnerabilities
    }

    fn detect_cumulative_errors(&self) -> Vec<RewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let reward_sigs = [&[0x3d, 0x18, 0xb9, 0x12][..], &[0xef, 0xa0, 0xf7, 0xca][..]];
        
        for sig in reward_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
                
                let has_last_update_tracking = window.windows(8).any(|w| {
                    w.contains(&0x54) && // SLOAD (lastUpdateTime)
                    w.contains(&0x42) && // TIMESTAMP
                    w.contains(&0x03)    // SUB (time delta)
                });
                
                let has_per_user_tracking = window.windows(6).any(|w| {
                    w.contains(&0x33) && // CALLER
                    w.contains(&0x54)    // SLOAD (user's last claim)
                });
                
                if !has_last_update_tracking || !has_per_user_tracking {
                    vulnerabilities.push(RewardVulnerability {
                        vulnerability_type: RewardVulnerabilityType::CumulativeRewardError,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Reward calculation doesn't properly track cumulative updates per user.".to_string(),
                        remediation: "Track per-user: reward = (currentRate - userLastRate) * userBalance".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_overflow_risks(&self) -> Vec<RewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 { // MUL (reward calculation)
                let window = &self.bytecode[i..i.saturating_add(30).min(self.bytecode.len())];
                
                let has_overflow_check = window.windows(5).any(|w| {
                    w.contains(&0x04) && // DIV (check result)
                    w.contains(&0x14) && // EQ (verify no overflow)
                    w.contains(&0x57)    // JUMPI (revert if overflow)
                });
                
                if !has_overflow_check {
                    vulnerabilities.push(RewardVulnerability {
                        vulnerability_type: RewardVulnerabilityType::RewardOverflow,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Reward multiplication lacks overflow protection. Can wrap around.".to_string(),
                        remediation: "Use SafeMath or checked arithmetic: reward.mul(rate)".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_rounding_errors(&self) -> Vec<RewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // DIV (rounding)
                let before = &self.bytecode[i.saturating_sub(10)..i];
                let after = &self.bytecode[i..i.saturating_add(10).min(self.bytecode.len())];
                
                let has_precision_loss_mitigation = before.contains(&0x02) || after.contains(&0x02);
                
                if !has_precision_loss_mitigation {
                    vulnerabilities.push(RewardVulnerability {
                        vulnerability_type: RewardVulnerabilityType::RoundingError,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Division in reward calculation can cause precision loss.".to_string(),
                        remediation: "Multiply first: (amount * rate) / PRECISION instead of (amount / PRECISION) * rate".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cumulative_error() {
        let bytecode = vec![0x3d, 0x18, 0xb9, 0x12, 0x02]; // claimReward + MUL (no tracking)
        let detector = RewardDistributionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RewardVulnerabilityType::CumulativeRewardError)));
    }
}
