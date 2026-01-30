use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalSpamVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ProposalSpammingDosDetector {
    bytecode: Vec<u8>,
}

impl ProposalSpammingDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ProposalSpamVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_proposal_threshold_bypass());
        vulnerabilities.extend(self.detect_active_proposal_limit());
        vulnerabilities.extend(self.detect_proposal_bond_requirement());

        vulnerabilities
    }

    fn detect_proposal_threshold_bypass(&self) -> Vec<ProposalSpamVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (proposal creation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_calldata = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (proposal data)
                
                if has_calldata {
                    let has_threshold_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_balance_check = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                    
                    if !has_threshold_check || !has_balance_check {
                        vulns.push(ProposalSpamVulnerability {
                            pc,
                            vulnerability_type: "ProposalThresholdBypass".to_string(),
                            description: format!(
                                "Proposal creation at PC {} without voting power threshold. Anyone can spam unlimited \
                                proposals regardless of token holdings. Attack: submit hundreds of proposals to dilute \
                                attention, hide malicious proposals, overwhelm governance participants. Missing: minimum \
                                token balance requirement (e.g., 1% of supply), voting power threshold, proposal fee. \
                                Enables governance DoS via proposal flooding.",
                                pc
                            ),
                            confidence: 0.88,
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

    fn detect_active_proposal_limit(&self) -> Vec<ProposalSpamVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (new proposal)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_counter = window.iter().any(|&b| b == 0x01); // ADD (incrementing proposal count)
                
                if has_counter {
                    let has_active_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_per_user_limit = window.iter().any(|&b| b == 0x33); // CALLER (checking per-user proposals)
                    
                    if !has_active_limit && !has_per_user_limit {
                        vulns.push(ProposalSpamVulnerability {
                            pc,
                            vulnerability_type: "ActiveProposalLimit".to_string(),
                            description: format!(
                                "Proposal counter at PC {} increments without active proposal cap. Unlimited concurrent \
                                proposals overwhelm governance UI, make finding legitimate proposals difficult. Attack: \
                                wealthy holder creates 1000s of active proposals simultaneously. Missing: maximum active \
                                proposals per address (e.g., 3), global active proposal limit, proposal cooldown period. \
                                Enables UX DoS attack on governance interface.",
                                pc
                            ),
                            confidence: 0.84,
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

    fn detect_proposal_bond_requirement(&self) -> Vec<ProposalSpamVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (proposal submission)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_value_transfer = window.iter().any(|&b| b == 0x34); // CALLVALUE
                let has_token_lock = window.iter().filter(|&&b| b == 0x03).count() >= 1; // SUB (locking tokens)
                
                if !has_value_transfer && !has_token_lock {
                    vulns.push(ProposalSpamVulnerability {
                        pc,
                        vulnerability_type: "ProposalBondRequirement".to_string(),
                        description: format!(
                            "Proposal submission at PC {} has no economic cost. Free proposal creation enables spam without \
                            consequences. Best practice: require refundable bond (returned if proposal passes/reaches quorum) \
                            or token locking during voting period. Missing: ETH bond deposit, token lock requirement, spam \
                            penalty mechanism. Without cost, malicious actors face no deterrent to spam attacks. \
                            Bond creates accountability and spam resistance.",
                            pc
                        ),
                        confidence: 0.82,
                    });
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
