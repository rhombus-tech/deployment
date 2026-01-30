use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncleBanditVariationsVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct UncleBanditVariationsDetector {
    bytecode: Vec<u8>,
}

impl UncleBanditVariationsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UncleBanditVariationsVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Uncle bandit attacks exploit uncle block rewards and timing
        // Detect uncle-inclusive block rewards creating manipulation incentive
        if let Some(location) = self.has_uncle_reward_manipulation() {
            vulnerabilities.push(UncleBanditVariationsVulnerability {
                vulnerability_type: "Uncle Block Reward Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Protocol rewards based on block inclusion without uncle consideration. Miners can deliberately create uncles to claim multiple rewards or manipulate timing. Use uncle-adjusted reward schemes.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect timestamp manipulation via uncle blocks
        if let Some(location) = self.has_uncle_timestamp_manipulation() {
            vulnerabilities.push(UncleBanditVariationsVulnerability {
                vulnerability_type: "Uncle Block Timestamp Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Timestamp-dependent logic without uncle block validation. Attackers can create uncle blocks with manipulated timestamps to game time-sensitive operations. Validate timestamp consistency across uncle chain.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect uncle rate manipulation for difficulty gaming
        if let Some(location) = self.has_difficulty_manipulation_via_uncles() {
            vulnerabilities.push(UncleBanditVariationsVulnerability {
                vulnerability_type: "Difficulty Manipulation via Uncle Rate".to_string(),
                location,
                severity: "Medium".to_string(),
                description: "Difficulty adjustment relies on uncle rate without manipulation resistance. Miners can artificially inflate uncle rate to reduce difficulty and increase block production profitability. Implement uncle rate caps or median filtering.".to_string(),
                confidence: "Low".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_uncle_reward_manipulation(&self) -> Option<usize> {
        // Pattern: Reward distribution based on block number without uncle checks
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for reward transfer (to COINBASE or similar)
            if self.bytecode[i] == 0x41 { // COINBASE
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 { // CALL (reward payment)
                        // Check if reward calculation considers uncles
                        let mut considers_uncles = false;
                        
                        for k in j.saturating_sub(35)..j {
                            // Look for uncle-related opcodes or storage reads
                            // Uncle data typically comes from external oracle or state
                            if self.bytecode[k] == 0x54 { // SLOAD
                                // Check if followed by uncle-related calculations
                                // This is heuristic - checking for multiple storage reads (uncle data)
                                let mut sload_count = 0;
                                for m in k..j {
                                    if self.bytecode[m] == 0x54 {
                                        sload_count += 1;
                                    }
                                }
                                if sload_count > 2 { // Multiple reads suggest uncle consideration
                                    considers_uncles = true;
                                }
                            }
                        }
                        
                        if !considers_uncles {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_uncle_timestamp_manipulation(&self) -> Option<usize> {
        // Pattern: Timestamp-dependent logic without block validation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in critical decision
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        // Check if there's block hash validation (to ensure canonical chain)
                        let mut validates_canonical = false;
                        
                        for k in i.saturating_sub(30)..i+30.min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x40 { // BLOCKHASH
                                // Check if compared (validating chain)
                                for m in k+1..(k+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x14 { // EQ
                                        validates_canonical = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !validates_canonical {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_difficulty_manipulation_via_uncles(&self) -> Option<usize> {
        // Pattern: Difficulty-based calculations without uncle rate limits
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for difficulty usage
            if self.bytecode[i] == 0x44 { // DIFFICULTY
                // Check if used in calculations
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL or DIV
                        // Check if there's uncle rate consideration
                        let mut considers_uncle_rate = false;
                        
                        for k in j.saturating_sub(30)..j+20.min(self.bytecode.len()) {
                            // Look for uncle count or rate calculation
                            // Typically involves storage reads and divisions
                            if self.bytecode[k] == 0x54 { // SLOAD
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x04 { // DIV (calculating rate)
                                        considers_uncle_rate = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !considers_uncle_rate {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
