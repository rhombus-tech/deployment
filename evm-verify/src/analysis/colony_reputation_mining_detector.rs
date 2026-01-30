use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColonyReputationMiningVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct ColonyReputationMiningDetector {
    bytecode: Vec<u8>,
}

impl ColonyReputationMiningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ColonyReputationMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Colony uses reputation mining for influence distribution
        // Detect reputation inflation attacks
        if let Some(location) = self.has_reputation_inflation() {
            vulnerabilities.push(ColonyReputationMiningVulnerability {
                vulnerability_type: "Colony Reputation Inflation Attack".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Reputation mining updates without Sybil resistance. Attackers create multiple identities to mine disproportionate reputation. Implement stake-weighted mining or identity verification.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect reputation decay bypass
        if let Some(location) = self.has_reputation_decay_bypass() {
            vulnerabilities.push(ColonyReputationMiningVulnerability {
                vulnerability_type: "Colony Reputation Decay Bypass".to_string(),
                location,
                severity: "High".to_string(),
                description: "Reputation does not decay over time allowing historical dominance. Inactive members retain voting power indefinitely. Implement time-based decay factor in reputation calculations.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect reputation tree manipulation
        if let Some(location) = self.has_reputation_tree_manipulation() {
            vulnerabilities.push(ColonyReputationMiningVulnerability {
                vulnerability_type: "Colony Reputation Tree Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Reputation merkle tree updates without fraud proofs. Malicious miners can submit invalid state roots. Require challenge period with slashing for invalid submissions.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_reputation_inflation(&self) -> Option<usize> {
        // Pattern: Reputation increment without rate limiting
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for reputation increase
            if self.bytecode[i] == 0x01 { // ADD (reputation += amount)
                // Check for rate limiting
                let mut has_rate_limit = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for time-based limit check
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Check if time delta validated
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 { // SUB (time delta)
                                has_rate_limit = true;
                                break;
                            }
                        }
                    }
                    // Or stake requirement
                    if self.bytecode[j] == 0x54 { // SLOAD (checking stake)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 { // LT (stake >= minimum)
                                has_rate_limit = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_rate_limit {
                    // Verify this is reputation update (SSTORE follows)
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (storing reputation)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_reputation_decay_bypass(&self) -> Option<usize> {
        // Pattern: Reputation read without decay calculation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for reputation loading
            if self.bytecode[i] == 0x54 { // SLOAD (reputation)
                // Check if decay applied
                let mut has_decay_calc = false;
                
                for j in i+1..i+30.min(self.bytecode.len()) {
                    // Look for time-based decay (timestamp comparison)
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Check for decay factor calculation
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x02 || self.bytecode[k] == 0x04 { // MUL/DIV (decay)
                                has_decay_calc = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_decay_calc {
                    // Verify this is used for voting/influence
                    for j in i+1..i+25.min(self.bytecode.len()) {
                        // Look for weight calculation or comparison
                        if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x10 { // MUL or LT
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_reputation_tree_manipulation(&self) -> Option<usize> {
        // Pattern: Merkle root update without challenge period
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for root hash storage
            if self.bytecode[i] == 0x55 { // SSTORE (merkle root)
                // Check for challenge period
                let mut has_challenge_period = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for timestamp check (challenge period)
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 { // ADD (timestamp + delay)
                                has_challenge_period = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_challenge_period {
                    // Verify this is reputation root (32-byte hash)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x20 { // SHA3 or root hash
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
