use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoVoteBuyingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DaoProposalVoteBuyingDetector {
    bytecode: Vec<u8>,
}

impl DaoProposalVoteBuyingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DaoVoteBuyingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_flashloan_voting_power());
        vulnerabilities.extend(self.detect_vote_delegation_market());
        vulnerabilities.extend(self.detect_voter_compensation_bribery());

        vulnerabilities
    }

    fn detect_flashloan_voting_power(&self) -> Vec<DaoVoteBuyingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x31 || opcode == 0x54 { // BALANCE, SLOAD (checking voting power)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_vote_cast = window.iter().any(|&b| b == 0x55); // SSTORE (recording vote)
                
                if has_vote_cast {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_snapshot = pre_window.iter().any(|&b| b == 0x43); // NUMBER (block snapshot)
                    let has_timelock = pre_window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_historical_balance = pre_window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_snapshot || !has_timelock || !has_historical_balance {
                        vulns.push(DaoVoteBuyingVulnerability {
                            pc,
                            vulnerability_type: "FlashloanVotingPower".to_string(),
                            description: format!(
                                "Voting power at PC {} uses current balance without snapshot. Attack: flashloan governance tokens, \
                                vote, return tokens in same transaction. Example: borrow 51% of supply, pass malicious proposal, \
                                repay loan. Missing: block snapshot requirement, voting delay period, historical balance check. \
                                Enables zero-cost governance attacks via temporary token acquisition.",
                                pc
                            ),
                            confidence: 0.91,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_vote_delegation_market(&self) -> Vec<DaoVoteBuyingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (delegation update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_delegatee = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_delegator = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_delegatee && has_delegator {
                    let has_payment_check = window.iter().any(|&b| b == 0x34); // CALLVALUE
                    let has_vote_lock = window.iter().any(|&b| b == 0x43); // NUMBER (lock period)
                    let has_single_use_delegation = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if has_payment_check && (!has_vote_lock || !has_single_use_delegation) {
                        vulns.push(DaoVoteBuyingVulnerability {
                            pc,
                            vulnerability_type: "VoteDelegationMarket".to_string(),
                            description: format!(
                                "Vote delegation at PC {} accepts payment without restrictions. Enables vote buying marketplace: \
                                voters sell delegation to highest bidder. Attack: wealthy party buys votes from many small holders \
                                to pass favorable proposals. Missing: unpaid delegation requirement, proposal-specific delegation locks, \
                                anti-bribery mechanisms. Creates secondary market for governance influence.",
                                pc
                            ),
                            confidence: 0.87,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_voter_compensation_bribery(&self) -> Vec<DaoVoteBuyingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (voter reward)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_vote_reference = window.iter().any(|&b| b == 0x54); // SLOAD (checking vote)
                let has_value = window.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_vote_reference && has_value {
                    let has_outcome_dependency = window.iter().any(|&b| b == 0x14); // EQ (checking vote side)
                    let has_protocol_treasury = window.iter().filter(|&&b| matches!(b, 0x73..=0x7F)).count() >= 1;
                    
                    if has_outcome_dependency && !has_protocol_treasury {
                        vulns.push(DaoVoteBuyingVulnerability {
                            pc,
                            vulnerability_type: "VoterCompensationBribery".to_string(),
                            description: format!(
                                "Voter compensation at PC {} rewards based on vote choice. External party can bribe voters by \
                                compensating those who vote specific way. Attack: create contract paying users for voting Yes, \
                                manipulating proposal outcome. Missing: outcome-independent rewards, protocol-only compensation, \
                                bribery detection. Enables vote buying through conditional payment mechanisms.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
