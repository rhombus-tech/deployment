use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuadraticVotingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct QuadraticVotingSybilAttackDetector {
    bytecode: Vec<u8>,
}

impl QuadraticVotingSybilAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<QuadraticVotingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_identity_verification_bypass());
        vulnerabilities.extend(self.detect_vote_splitting_exploit());
        vulnerabilities.extend(self.detect_collusion_resistance_failure());

        vulnerabilities
    }

    fn detect_identity_verification_bypass(&self) -> Vec<QuadraticVotingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (quadratic cost calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_vote_count = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_vote_count {
                    let has_identity_proof = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    let has_unique_human_check = window.iter().any(|&b| b == 0x08); // bn256Pairing (ZK proof)
                    let has_sybil_resistance = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_identity_proof || !has_unique_human_check || !has_sybil_resistance {
                        vulns.push(QuadraticVotingVulnerability {
                            pc,
                            vulnerability_type: "IdentityVerificationBypass".to_string(),
                            description: format!(
                                "Quadratic voting at PC {} without Sybil resistance. Quadratic voting assumes one-person-one-vote; \
                                cost = votes². Attack: create N identities, each voting 1 unit costs N; single identity voting N costs N². \
                                Sybil attack defeats quadratic fairness. Missing: proof-of-unique-human, BrightID integration, \
                                identity verification. Quadratic voting requires identity uniqueness to function properly.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_vote_splitting_exploit(&self) -> Vec<QuadraticVotingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (recording vote)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_voter_id = window.iter().any(|&b| b == 0x33); // CALLER
                let has_vote_amount = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_voter_id && has_vote_amount {
                    let has_consolidation_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    let has_total_vote_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_consolidation_check || !has_total_vote_limit {
                        vulns.push(QuadraticVotingVulnerability {
                            pc,
                            vulnerability_type: "VoteSplittingExploit".to_string(),
                            description: format!(
                                "Vote recording at PC {} allows splitting across identities. Even with unique identity, voter can \
                                split tokens across family/friends to reduce quadratic cost. Example: 100 votes from 1 address costs 10,000; \
                                split to 10 addresses voting 10 each costs 1,000 total. Missing: vote consolidation detection, \
                                address clustering analysis, total vote limits per entity. Defeats quadratic voting's anti-plutocracy goal.",
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

    fn detect_collusion_resistance_failure(&self) -> Vec<QuadraticVotingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (vote submission)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_vote_recording = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_vote_recording {
                    let has_encryption = window.iter().any(|&b| b == 0x08); // bn256Pairing (ZK/encryption)
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 2; // Multiple KECCAK256
                    let has_maci = window.iter().any(|&b| b == 0x01); // ECRECOVER (MACI signature)
                    
                    if !has_encryption && !has_commit_reveal && !has_maci {
                        vulns.push(QuadraticVotingVulnerability {
                            pc,
                            vulnerability_type: "CollusionResistanceFailure".to_string(),
                            description: format!(
                                "Vote submission at PC {} reveals choices before voting ends. Enables vote buying verification: \
                                buyer sees how voter voted, can confirm bribe was effective. Also enables coercion: voter proves vote \
                                to avoid punishment. Missing: vote encryption, MACI (Minimal Anti-Collusion Infrastructure), commit-reveal \
                                with randomization. Transparent voting undermines quadratic voting's collusion resistance.",
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
