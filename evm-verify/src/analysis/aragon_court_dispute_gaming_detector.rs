use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AragonCourtDisputeGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct AragonCourtDisputeGamingDetector {
    bytecode: Vec<u8>,
}

impl AragonCourtDisputeGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AragonCourtDisputeGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Aragon Court uses juror selection for dispute resolution
        // Detect juror selection gaming
        if let Some(location) = self.has_juror_selection_gaming() {
            vulnerabilities.push(AragonCourtDisputeGamingVulnerability {
                vulnerability_type: "Aragon Court Juror Selection Gaming".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Juror selection uses predictable randomness or insufficient stake weighting. Attackers can predict selection and stake tokens to influence specific disputes. Use VRF with commit-reveal and minimum stake distribution.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect appeal bribery
        if let Some(location) = self.has_appeal_bribery_risk() {
            vulnerabilities.push(AragonCourtDisputeGamingVulnerability {
                vulnerability_type: "Aragon Court Appeal Bribery".to_string(),
                location,
                severity: "High".to_string(),
                description: "Appeal process allows unlimited juror pool growth without collusion detection. Wealthy parties can stake heavily to dominate appeal rounds. Implement diminishing returns or appeal limits.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect commit-reveal bypass
        if let Some(location) = self.has_commit_reveal_bypass() {
            vulnerabilities.push(AragonCourtDisputeGamingVulnerability {
                vulnerability_type: "Aragon Court Commit-Reveal Bypass".to_string(),
                location,
                severity: "High".to_string(),
                description: "Vote commitment without salt allows vote prediction via brute force. Last juror can see likely outcome before committing. Require unique salt per vote and validate salt randomness.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_juror_selection_gaming(&self) -> Option<usize> {
        // Pattern: Juror selection using block hash without future block commitment
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for randomness source
            if self.bytecode[i] == 0x40 { // BLOCKHASH
                // Check if selection uses this randomness
                let mut has_selection_logic = false;
                
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 { // MOD (selecting juror index)
                        has_selection_logic = true;
                        break;
                    }
                }
                
                if has_selection_logic {
                    // Check for commit-reveal pattern (future block commitment)
                    let mut has_commit_reveal = false;
                    
                    for j in i.saturating_sub(30)..i {
                        // Look for committed block number
                        if self.bytecode[j] == 0x54 { // SLOAD (committed future block)
                            has_commit_reveal = true;
                        }
                    }
                    
                    if !has_commit_reveal {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_appeal_bribery_risk(&self) -> Option<usize> {
        // Pattern: Appeal stake acceptance without whale limits
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for appeal stake storage
            if self.bytecode[i] == 0x55 { // SSTORE (appeal stake)
                // Check for stake size limits
                let mut has_stake_limit = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for maximum stake check
                    if self.bytecode[j] == 0x10 { // LT (stake < maximum)
                        has_stake_limit = true;
                    }
                    // Or proportional limit based on total
                    if self.bytecode[j] == 0x04 { // DIV (calculating proportion)
                        has_stake_limit = true;
                    }
                }
                
                if !has_stake_limit {
                    // Verify this is appeal-related (multiple rounds)
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x01 { // ADD (incrementing round)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_commit_reveal_bypass(&self) -> Option<usize> {
        // Pattern: Vote commitment without salt requirement
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for commitment storage (hash of vote)
            if self.bytecode[i] == 0x55 { // SSTORE (commitment)
                // Check if salt is included in hash
                let mut has_salt_in_hash = false;
                
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x20 { // SHA3 (commitment hash)
                        // Check if multiple values hashed (vote + salt)
                        // Look for multiple MSTORE operations before SHA3
                        let mut mstore_count = 0;
                        for k in j.saturating_sub(20)..j {
                            if self.bytecode[k] == 0x52 { // MSTORE
                                mstore_count += 1;
                            }
                        }
                        if mstore_count >= 2 { // vote + salt
                            has_salt_in_hash = true;
                        }
                    }
                }
                
                if !has_salt_in_hash {
                    // Verify this is voting (juror address involved)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x33 { // CALLER (juror)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
