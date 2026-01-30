use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumManipulationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OffChainGovernanceForumManipulationDetector {
    bytecode: Vec<u8>,
}

impl OffChainGovernanceForumManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ForumManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_off_chain_proposal_hash_mismatch());
        vulnerabilities.extend(self.detect_forum_sybil_resistance());
        vulnerabilities.extend(self.detect_proposal_censorship_risk());

        vulnerabilities
    }

    fn detect_off_chain_proposal_hash_mismatch(&self) -> Vec<ForumManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (proposal hash)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_calldata = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_calldata {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_storage_compare = forward.iter().any(|&b| b == 0x14); // EQ
                    let has_ipfs_reference = window.iter().filter(|&&b| b >= 0x60 && b <= 0x7F).count() > 2;
                    
                    if !has_storage_compare && !has_ipfs_reference {
                        vulns.push(ForumManipulationVulnerability {
                            pc,
                            vulnerability_type: "OffChainProposalHashMismatch".to_string(),
                            description: format!(
                                "Proposal hash at PC {} computed from on-chain data without off-chain verification link. \
                                Attack: proposal passes on-chain vote but off-chain forum discussion was about different proposal. \
                                Users vote yes thinking they support forum proposal, but on-chain executes different code. \
                                Missing: IPFS hash verification, forum post canonical link, content hash validation. \
                                Enables bait-and-switch governance attacks.",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_forum_sybil_resistance(&self) -> Vec<ForumManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 || opcode == 0x08 { // Signature verification
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_signature_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_signature_data {
                    let has_token_balance = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                    let has_historical_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_token_balance && !has_historical_check {
                        vulns.push(ForumManipulationVulnerability {
                            pc,
                            vulnerability_type: "ForumSybilResistance".to_string(),
                            description: format!(
                                "Forum signature verification at PC {} without Sybil resistance. Anyone can create unlimited \
                                accounts to spam proposals, manipulate sentiment, create fake consensus. Missing: token-gated \
                                participation, voting power weighting, account age requirements. Enables: astroturfing campaigns, \
                                false consensus manufacturing, proposal spam attacks.",
                                pc
                            ),
                            confidence: 0.83,
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

    fn detect_proposal_censorship_risk(&self) -> Vec<ForumManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (proposal submission)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_check = window.iter().any(|&b| b == 0x33); // CALLER
                let has_approval = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ checks
                
                if has_admin_check && has_approval {
                    let has_decentralized_fallback = window.iter().filter(|&&b| b == 0x57).count() > 2; // Multiple JUMPI
                    
                    if !has_decentralized_fallback {
                        vulns.push(ForumManipulationVulnerability {
                            pc,
                            vulnerability_type: "ProposalCensorshipRisk".to_string(),
                            description: format!(
                                "Proposal submission at PC {} requires admin/moderator approval. Centralized gatekeeping \
                                enables censorship of controversial proposals, suppression of minority opinions, selective \
                                silencing. Missing: permissionless proposal submission path, decentralized moderation, \
                                censorship-resistant fallback. Forum admins control which ideas reach governance vote, \
                                violating decentralization principles.",
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
}
