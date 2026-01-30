use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaveGovernanceShortTimelockVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct AaveGovernanceShortTimelockDetector {
    bytecode: Vec<u8>,
}

impl AaveGovernanceShortTimelockDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AaveGovernanceShortTimelockVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Aave uses short execution timelock for governance
        // Detect insufficient timelock period
        if let Some(location) = self.has_insufficient_timelock() {
            vulnerabilities.push(AaveGovernanceShortTimelockVulnerability {
                vulnerability_type: "Aave Governance Short Timelock".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Proposal timelock under 24 hours insufficient for community response. Flash governance attacks can execute before adequate review. Require minimum 48-72 hour timelock for high-impact proposals.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect timelock bypass via executor privileges
        if let Some(location) = self.has_executor_privilege_bypass() {
            vulnerabilities.push(AaveGovernanceShortTimelockVulnerability {
                vulnerability_type: "Aave Executor Privilege Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Executor role can bypass timelock for critical operations. Compromised executor can execute malicious proposals immediately. Require timelock even for executor role or use multi-sig.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect voting period manipulation
        if let Some(location) = self.has_voting_period_manipulation() {
            vulnerabilities.push(AaveGovernanceShortTimelockVulnerability {
                vulnerability_type: "Aave Voting Period Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Voting period can be shortened dynamically. Governance can rush proposals through with minimal notice. Make voting period immutable or require supermajority to change.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_insufficient_timelock(&self) -> Option<usize> {
        // Pattern: Timelock check with short delay constant
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for timelock validation
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Look for delay addition
                for j in (i+1)..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { // ADD (timestamp + delay)
                        // Check delay constant (looking for PUSH)
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] >= 0x60 && self.bytecode[k] <= 0x7f { // PUSH
                                // Check if delay is small (< 86400 = 1 day)
                                if k + 1 < self.bytecode.len() {
                                    let delay_bytes = &self.bytecode[k+1..std::cmp::min(k+4, self.bytecode.len())];
                                    // Simple heuristic: if first byte is < 2, likely too short
                                    if !delay_bytes.is_empty() && delay_bytes[0] < 2 {
                                        return Some(i);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_executor_privilege_bypass(&self) -> Option<usize> {
        // Pattern: Execution without timelock check for privileged role
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for execution call
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Check if executor role bypasses timelock
                let mut has_role_check = false;
                let mut has_timelock_check = false;
                
                for j in i.saturating_sub(45)..i {
                    // Look for role check (executor)
                    if self.bytecode[j] == 0x33 { // CALLER
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (executor check)
                                has_role_check = true;
                                break;
                            }
                        }
                    }
                    // Look for timelock check
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_timelock_check = true;
                                break;
                            }
                        }
                    }
                }
                
                // If role check exists but no timelock, this is bypass
                if has_role_check && !has_timelock_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_voting_period_manipulation(&self) -> Option<usize> {
        // Pattern: Voting period storage update without restrictions
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for voting period update
            if self.bytecode[i] == 0x55 { // SSTORE (voting period)
                // Check for supermajority requirement
                let mut has_supermajority_check = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for vote threshold check
                    if self.bytecode[j] == 0x04 { // DIV (calculating percentage)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            // Check if compared against high threshold (e.g., 66% = 2/3)
                            if self.bytecode[k] == 0x11 { // GT
                                // This might be supermajority, but hard to verify exact threshold
                                has_supermajority_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_supermajority_check {
                    // Verify this is governance parameter (small value)
                    for j in i.saturating_sub(10)..i {
                        if self.bytecode[j] >= 0x60 && self.bytecode[j] <= 0x62 { // PUSH1-PUSH3
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
