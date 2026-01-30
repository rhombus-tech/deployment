use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapGovernanceQuorumVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct UniswapGovernanceQuorumDetector {
    bytecode: Vec<u8>,
}

impl UniswapGovernanceQuorumDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UniswapGovernanceQuorumVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Uniswap governance requires quorum for proposal passage
        // Detect quorum manipulation via flash loans
        if let Some(location) = self.has_quorum_flash_loan_attack() {
            vulnerabilities.push(UniswapGovernanceQuorumVulnerability {
                vulnerability_type: "Uniswap Governance Quorum Flash Loan Attack".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Quorum calculated using current balance without snapshot. Attackers can flash loan tokens to reach quorum then repay. Use checkpoint-based voting power from proposal creation block.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect proposal threshold manipulation
        if let Some(location) = self.has_proposal_threshold_manipulation() {
            vulnerabilities.push(UniswapGovernanceQuorumVulnerability {
                vulnerability_type: "Uniswap Proposal Threshold Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Proposal creation threshold checked at submission without delegation lock. Attackers can temporarily acquire tokens, submit proposal, then transfer tokens. Require sustained token holding period.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect vote buying coordination
        if let Some(location) = self.has_vote_buying_risk() {
            vulnerabilities.push(UniswapGovernanceQuorumVulnerability {
                vulnerability_type: "Uniswap Vote Buying Coordination".to_string(),
                location,
                severity: "High".to_string(),
                description: "Voting power transferable during active proposals. Vote markets can coordinate to swing outcomes. Lock voting power or delegation during proposal period.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_quorum_flash_loan_attack(&self) -> Option<usize> {
        // Pattern: Quorum check using current balance instead of snapshot
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for quorum calculation
            if self.bytecode[i] == 0x04 { // DIV (votes / total)
                // Check if using checkpoint/snapshot
                let mut uses_checkpoint = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for block number in storage key (snapshot)
                    if self.bytecode[j] == 0x43 { // NUMBER
                        // Check if used in mapping lookup
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x20 { // SHA3 (checkpoint mapping)
                                uses_checkpoint = true;
                                break;
                            }
                        }
                    }
                }
                
                if !uses_checkpoint {
                    // Verify this is quorum check (threshold comparison)
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_proposal_threshold_manipulation(&self) -> Option<usize> {
        // Pattern: Proposal threshold check without historical requirement
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for proposal creation threshold check
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT/GT (threshold check)
                // Check if uses historical/averaged balance
                let mut uses_historical = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for multiple block checkpoints (averaged)
                    if self.bytecode[j] == 0x43 { // NUMBER
                        // Check if subtracted (past blocks)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 { // SUB (past block)
                                uses_historical = true;
                                break;
                            }
                        }
                    }
                }
                
                if !uses_historical {
                    // Verify this is proposal threshold (SSTORE of proposal follows)
                    for j in i+1..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (creating proposal)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_vote_buying_risk(&self) -> Option<usize> {
        // Pattern: Vote casting without delegation lock check
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for vote recording
            if self.bytecode[i] == 0x55 { // SSTORE (recording vote)
                // Check if delegation is locked during voting
                let mut has_delegation_lock = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for active proposal check preventing delegation change
                    if self.bytecode[j] == 0x54 { // SLOAD (proposal state)
                        // Check if prevents concurrent delegation
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (active proposal)
                                has_delegation_lock = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_delegation_lock {
                    // Verify this is voting (proposal ID involved)
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (proposalId)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
