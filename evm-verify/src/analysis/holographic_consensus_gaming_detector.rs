use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolographicConsensusGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct HolographicConsensusGamingDetector {
    bytecode: Vec<u8>,
}

impl HolographicConsensusGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HolographicConsensusGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Holographic consensus uses relative majority (not absolute)
        // Detect relative majority manipulation
        if let Some(location) = self.has_relative_majority_manipulation() {
            vulnerabilities.push(HolographicConsensusGamingVulnerability {
                vulnerability_type: "Holographic Consensus Relative Majority Attack".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Proposal passes with relative majority without minimum participation threshold. Low turnout allows minority control (e.g., 51% of 10% participation). Require minimum quorum like absolute threshold.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect boosting stake manipulation
        if let Some(location) = self.has_boosting_stake_gaming() {
            vulnerabilities.push(HolographicConsensusGamingVulnerability {
                vulnerability_type: "Holographic Consensus Boosting Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Boosting stake calculation without spam protection. Attackers can boost low-value proposals to bypass normal approval process. Implement boosting cost proportional to proposal impact.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect prediction market manipulation
        if let Some(location) = self.has_prediction_market_manipulation() {
            vulnerabilities.push(HolographicConsensusGamingVulnerability {
                vulnerability_type: "Holographic Consensus Prediction Market Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Prediction market for proposal outcomes without collusion prevention. Coordinated betting can manipulate boosting decisions and proposal priority. Add slashing for coordinated manipulation.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_relative_majority_manipulation(&self) -> Option<usize> {
        // Pattern: Vote counting with division but no minimum threshold
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for majority calculation (yes > no)
            if self.bytecode[i] == 0x04 { // DIV (calculating percentage)
                // Check if compared for majority (GT 50%)
                let mut has_majority_check = false;
                let mut has_quorum_check = false;
                
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 { // GT (yes > no)
                        has_majority_check = true;
                    }
                }
                
                // Check for absolute quorum (total votes > minimum)
                for j in i.saturating_sub(25)..i+25.min(self.bytecode.len()) {
                    // Look for comparison with minimum threshold constant
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        // Check if comparing total votes
                        for k in j.saturating_sub(5)..j {
                            if self.bytecode[k] == 0x01 { // ADD (total = yes + no)
                                has_quorum_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_majority_check && !has_quorum_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_boosting_stake_gaming(&self) -> Option<usize> {
        // Pattern: Boosting deposit without cost validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for boosting stake storage
            if self.bytecode[i] == 0x55 { // SSTORE (boosting stake)
                // Check if stake amount is validated
                let mut has_stake_validation = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for minimum stake check
                    if self.bytecode[j] == 0x10 { // LT (stake >= minimum)
                        has_stake_validation = true;
                    }
                    // Or proportional cost calculation
                    if self.bytecode[j] == 0x02 { // MUL (stake * factor)
                        has_stake_validation = true;
                    }
                }
                
                if !has_stake_validation {
                    // Verify this is boosting-related
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

    fn has_prediction_market_manipulation(&self) -> Option<usize> {
        // Pattern: Prediction bet acceptance without collusion detection
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE (recording bet)
                // Check for large bet detection
                let mut has_whale_protection = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for bet size limit check
                    if self.bytecode[j] == 0x10 { // LT (bet < maximum)
                        has_whale_protection = true;
                    }
                }
                
                if !has_whale_protection {
                    // Verify this is prediction market related (value transfer)
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x34 { // CALLVALUE (bet amount)
                            // Check if this is binary prediction (two outcomes)
                            for k in i.saturating_sub(15)..i {
                                if self.bytecode[k] == 0x15 { // ISZERO (boolean outcome)
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
