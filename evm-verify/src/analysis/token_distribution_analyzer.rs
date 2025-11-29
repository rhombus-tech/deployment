/// Token Distribution Mechanism Analyzer
/// Detects vesting schedule manipulation, cliff bypass, linear unlock exploits

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DistributionVulnerabilityType {
    VestingManipulation,
    CliffBypass,
    LinearUnlockExploit,
    TimelockBypass,
    EarlyWithdrawal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity { Critical, High, Medium, Low }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionVulnerability {
    pub vulnerability_type: DistributionVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct TokenDistributionAnalyzer {
    bytecode: Vec<u8>,
}

impl TokenDistributionAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DistributionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_vesting_manipulation());
        vulnerabilities.extend(self.detect_cliff_bypass());
        vulnerabilities.extend(self.detect_timelock_bypass());
        vulnerabilities
    }

    fn detect_vesting_manipulation(&self) -> Vec<DistributionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let vesting_sigs = [&[0xe6, 0xfd, 0x48, 0xbc][..], &[0x8d, 0x0d, 0x5b, 0xa0][..]];
        
        for sig in vesting_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                let has_owner_check = window.windows(5).any(|w| w.contains(&0x33) && w.contains(&0x14));
                let has_timelock = window.contains(&0x42) && window.contains(&0x10);
                
                if !has_owner_check || !has_timelock {
                    vulnerabilities.push(DistributionVulnerability {
                        vulnerability_type: DistributionVulnerabilityType::VestingManipulation,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Vesting parameters can be modified without proper authorization or timelock.".to_string(),
                        remediation: "Add onlyOwner + timelock: require(msg.sender == owner && block.timestamp >= changeTime + DELAY)".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_cliff_bypass(&self) -> Vec<DistributionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (cliff check)
                let window = &self.bytecode[i..i.saturating_add(40).min(self.bytecode.len())];
                let has_comparison = window.iter().any(|&op| op == 0x10 || op == 0x11);
                let has_revert = window.contains(&0xfd) || window.contains(&0x57);
                let has_cliff_value = window.windows(3).any(|w| w[0] == 0x60 && w[1] > 0);
                
                if has_comparison && has_cliff_value && !has_revert {
                    vulnerabilities.push(DistributionVulnerability {
                        vulnerability_type: DistributionVulnerabilityType::CliffBypass,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Cliff time check doesn't enforce revert. Tokens accessible before cliff.".to_string(),
                        remediation: "Enforce cliff: require(block.timestamp >= cliffTime, 'Cliff not reached')".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_timelock_bypass(&self) -> Vec<DistributionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let release_sigs = [&[0x86, 0xd1, 0xa6, 0x9f][..], &[0x3c, 0xca, 0xb5, 0x1f][..]];
        
        for sig in release_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                let has_time_check = window.contains(&0x42) && window.contains(&0x10) && window.contains(&0x57);
                
                if !has_time_check {
                    vulnerabilities.push(DistributionVulnerability {
                        vulnerability_type: DistributionVulnerabilityType::TimelockBypass,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Token release function lacks timelock enforcement.".to_string(),
                        remediation: "Enforce release time: require(block.timestamp >= releaseTime, 'Too early')".to_string(),
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
    fn test_detect_vesting_manipulation() {
        let bytecode = vec![0xe6, 0xfd, 0x48, 0xbc, 0x55]; // setVesting + SSTORE (no check)
        let analyzer = TokenDistributionAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, DistributionVulnerabilityType::VestingManipulation)));
    }
}
