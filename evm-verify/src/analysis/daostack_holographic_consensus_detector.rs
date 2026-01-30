use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaostackHolographicConsensusVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct DaostackHolographicConsensusDetector {
    bytecode: Vec<u8>,
}

impl DaostackHolographicConsensusDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DaostackHolographicConsensusVulnerability> {
        let mut vulnerabilities = Vec::new();

        // DAOstack holographic consensus uses stake-based boosting
        // Detect boosting stake manipulation
        if let Some(location) = self.has_boosting_stake_manipulation() {
            vulnerabilities.push(DaostackHolographicConsensusVulnerability {
                vulnerability_type: "DAOstack Boosting Stake Manipulation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Boosting stake without anti-whale limits. Single wealthy party can boost malicious proposals to bypass normal voting thresholds. Implement maximum stake per address or quadratic boosting.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect boosting reward gaming
        if let Some(location) = self.has_boosting_reward_gaming() {
            vulnerabilities.push(DaostackHolographicConsensusVulnerability {
                vulnerability_type: "DAOstack Boosting Reward Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Boosting rewards calculated without slashing risk. Predictors can game rewards by coordinating on obvious outcomes without real prediction value. Add slashing for failed predictions.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect reputation-based voting bypass
        if let Some(location) = self.has_reputation_voting_bypass() {
            vulnerabilities.push(DaostackHolographicConsensusVulnerability {
                vulnerability_type: "DAOstack Reputation Voting Bypass".to_string(),
                location,
                severity: "High".to_string(),
                description: "Boosted proposals bypass reputation-weighted voting. Low-reputation attackers can force execution via staking without community support. Require minimum reputation participation even for boosted proposals.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_boosting_stake_manipulation(&self) -> Option<usize> {
        // Pattern: Boosting stake storage without per-address limit
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE (boosting stake)
                // Check for per-address stake limit
                let mut has_address_limit = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for address-specific stake check
                    if self.bytecode[j] == 0x54 { // SLOAD (existing address stake)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 { // LT (stake < max per address)
                                has_address_limit = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_address_limit {
                    // Verify this is boosting (upstake/downstake)
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x34 { // CALLVALUE (boosting payment)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_boosting_reward_gaming(&self) -> Option<usize> {
        // Pattern: Reward distribution without slashing mechanism
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for reward transfer
            if self.bytecode[i] == 0xf1 { // CALL (reward payout)
                // Check for slashing logic (conditional transfer)
                let mut has_slashing = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for outcome verification
                    if self.bytecode[j] == 0x14 { // EQ (predicted == actual)
                        // Check if false prediction leads to slashing
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (prediction wrong)
                                // Should lead to no reward or slashing
                                has_slashing = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_slashing {
                    // Verify this is boosting reward (proportional calc)
                    for j in i.saturating_sub(30)..i {
                        if self.bytecode[j] == 0x04 { // DIV (proportional reward)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_reputation_voting_bypass(&self) -> Option<usize> {
        // Pattern: Proposal execution based on boosting without reputation check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for execution trigger
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL (execution)
                // Check if boosting allows bypass
                let mut checks_reputation = false;
                
                for j in i.saturating_sub(45)..i {
                    // Look for reputation-weighted vote check
                    if self.bytecode[j] == 0x54 { // SLOAD (reputation)
                        // Check if reputation used in threshold calculation
                        for k in j+1..(j+20).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x02 { // MUL (reputation * votes)
                                checks_reputation = true;
                                break;
                            }
                        }
                    }
                }
                
                if !checks_reputation {
                    // Verify this is boosted proposal execution
                    for j in i.saturating_sub(35)..i {
                        // Look for boosting stake check
                        if self.bytecode[j] == 0x54 { // SLOAD (boost amount)
                            for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // Threshold
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
