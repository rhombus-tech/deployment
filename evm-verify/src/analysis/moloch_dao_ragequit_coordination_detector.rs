use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MolochRagequitCoordinationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct MolochDaoRagequitCoordinationDetector {
    bytecode: Vec<u8>,
}

impl MolochDaoRagequitCoordinationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MolochRagequitCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Moloch DAO ragequit allows members to exit with proportional assets
        // Detect coordinated ragequit attack
        if let Some(location) = self.has_coordinated_ragequit_risk() {
            vulnerabilities.push(MolochRagequitCoordinationVulnerability {
                vulnerability_type: "Moloch DAO Coordinated Ragequit Attack".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Ragequit allows immediate withdrawal of proportional assets without exit penalty. Coordinated mass exit by majority can drain treasury leaving minority with worthless shares. Implement exit queue or gradual unlock.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect ragequit front-running
        if let Some(location) = self.has_ragequit_frontrunning() {
            vulnerabilities.push(MolochRagequitCoordinationVulnerability {
                vulnerability_type: "Moloch DAO Ragequit Front-Running".to_string(),
                location,
                severity: "High".to_string(),
                description: "Share valuation for ragequit uses current state without lock. Attackers can front-run dilutive proposals by ragequitting before execution. Lock ragequit during proposal grace period.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect guild bank drainage
        if let Some(location) = self.has_guild_bank_drainage() {
            vulnerabilities.push(MolochRagequitCoordinationVulnerability {
                vulnerability_type: "Moloch DAO Guild Bank Drainage".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Ragequit calculates proportional share without minimum reserve protection. Complete treasury drain leaves DAO unable to operate. Require minimum operational reserve (e.g., 20%).".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_coordinated_ragequit_risk(&self) -> Option<usize> {
        // Pattern: Ragequit withdrawal without exit queue or delay
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for proportional withdrawal calculation
            if self.bytecode[i] == 0x04 { // DIV (share / totalShares)
                // Check if followed by MUL (proportion * treasury)
                let mut has_proportional_calc = false;
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL
                        has_proportional_calc = true;
                        break;
                    }
                }
                
                if has_proportional_calc {
                    // Check for exit delay/queue
                    let mut has_exit_delay = false;
                    
                    for j in i.saturating_sub(30)..i+30.min(self.bytecode.len()) {
                        // Look for timestamp comparison (exit delay)
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                    has_exit_delay = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_exit_delay {
                        // Check if followed by transfer (immediate withdrawal)
                        for j in i+1..i+30.min(self.bytecode.len()) {
                            if self.bytecode[j] == 0xf1 { // CALL (transfer)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_ragequit_frontrunning(&self) -> Option<usize> {
        // Pattern: Share value calculation without proposal grace period check
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x04 { // DIV (share valuation)
                // Check for grace period validation
                let mut has_grace_period_check = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for proposal state check
                    if self.bytecode[j] == 0x54 { // SLOAD (proposal state)
                        // Check if proposal is in grace period
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (state check)
                                has_grace_period_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_grace_period_check {
                    // Verify this is ragequit (burn shares pattern)
                    for j in i+1..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (burning shares)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_guild_bank_drainage(&self) -> Option<usize> {
        // Pattern: Treasury withdrawal without minimum reserve check
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for balance transfer
            if self.bytecode[i] == 0xf1 { // CALL (withdrawal)
                // Check if minimum reserve is enforced
                let mut has_reserve_check = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for remaining balance check
                    if self.bytecode[j] == 0x03 { // SUB (remaining = total - withdrawal)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 { // LT (remaining >= minimum)
                                has_reserve_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_reserve_check {
                    // Verify this is ragequit withdrawal (proportional calc before)
                    for j in i.saturating_sub(30)..i {
                        if self.bytecode[j] == 0x04 { // DIV (proportional)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
