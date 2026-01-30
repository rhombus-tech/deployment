use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundAutonomousProposalVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct CompoundAutonomousProposalDetector {
    bytecode: Vec<u8>,
}

impl CompoundAutonomousProposalDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompoundAutonomousProposalVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Compound Autonomous Proposals execute automatically
        // Detect autonomous execution without sufficient validation
        if let Some(location) = self.has_autonomous_execution_risk() {
            vulnerabilities.push(CompoundAutonomousProposalVulnerability {
                vulnerability_type: "Compound Autonomous Proposal Execution Risk".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Autonomous proposal execution without emergency pause. Malicious proposals execute automatically after timelock with no last-minute intervention mechanism. Implement guardian veto or pause function.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect quorum manipulation
        if let Some(location) = self.has_quorum_manipulation() {
            vulnerabilities.push(CompoundAutonomousProposalVulnerability {
                vulnerability_type: "Compound Governance Quorum Manipulation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Quorum calculated at proposal end without snapshot. Attackers can borrow tokens temporarily to reach quorum then return them. Use vote snapshot at proposal creation block.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect delegate vote buying
        if let Some(location) = self.has_delegate_vote_buying() {
            vulnerabilities.push(CompoundAutonomousProposalVulnerability {
                vulnerability_type: "Compound Delegate Vote Buying".to_string(),
                location,
                severity: "High".to_string(),
                description: "Delegation without minimum delegation period. Attackers can buy votes (delegate to themselves) just before voting, then sell after. Require minimum delegation lock period.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_autonomous_execution_risk(&self) -> Option<usize> {
        // Pattern: Proposal execution without guardian check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for proposal execution
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Check for guardian/pause mechanism
                let mut has_guardian_check = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for guardian authorization or pause state
                    if self.bytecode[j] == 0x54 { // SLOAD (guardian or pause state)
                        // Check if validated
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (not paused)
                                has_guardian_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_guardian_check {
                    // Verify this is proposal execution (timelock check before)
                    for j in i.saturating_sub(35)..i {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP (timelock check)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_quorum_manipulation(&self) -> Option<usize> {
        // Pattern: Quorum check using current supply instead of snapshot
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for quorum calculation
            if self.bytecode[i] == 0x04 { // DIV (votes / totalSupply)
                // Check if totalSupply is from snapshot
                let mut uses_snapshot = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for block number in storage key (snapshot)
                    if self.bytecode[j] == 0x43 { // NUMBER
                        // Check if used in storage key computation
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x20 { // SHA3 (mapping with block)
                                uses_snapshot = true;
                                break;
                            }
                        }
                    }
                }
                
                if !uses_snapshot {
                    // Verify this is quorum check
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT (threshold)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_delegate_vote_buying(&self) -> Option<usize> {
        // Pattern: Delegation change without timelock
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for delegation update
            if self.bytecode[i] == 0x55 { // SSTORE (setting delegate)
                // Check for delegation lock period
                let mut has_lock_period = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for timestamp check (lock period)
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 { // ADD (timestamp + lock)
                                has_lock_period = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_lock_period {
                    // Verify this is delegation (delegatee address stored)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (delegatee address)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
