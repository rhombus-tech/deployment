use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRevealVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CommitRevealEarlyRevealAttackDetector {
    bytecode: Vec<u8>,
}

impl CommitRevealEarlyRevealAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_commit_phase_enforcement());
        vulnerabilities.extend(self.detect_reveal_frontrunning());
        vulnerabilities.extend(self.detect_commitment_binding_weakness());

        vulnerabilities
    }

    fn detect_missing_commit_phase_enforcement(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (commitment hash)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_input = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_user_input {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_storage = forward.iter().any(|&b| b == 0x55); // SSTORE (storing commitment)
                    
                    if has_storage {
                        let has_phase_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP (phase validation)
                        let has_reveal_block = forward.iter().any(|&b| b == 0x57); // JUMPI (preventing reveal)
                        
                        if !has_phase_check || !has_reveal_block {
                            vulns.push(CommitRevealVulnerability {
                                pc,
                                vulnerability_type: "MissingCommitPhaseEnforcement".to_string(),
                                description: format!(
                                    "Commit-reveal at PC {} doesn't enforce phase separation. Users can reveal values during commit phase. \
                                    Attack: see others' commitments, calculate their values, submit optimal response immediately. Missing: \
                                    commit phase deadline, reveal phase start time, phase-gated function access. Commit and reveal must be \
                                    temporally separated to prevent information leakage.",
                                    pc
                                ),
                                confidence: 0.89,
                            });
                        }
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

    fn detect_reveal_frontrunning(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (reveal data)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_hash_verification = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_commitment_check = window.iter().any(|&b| b == 0x14); // EQ
                
                if has_hash_verification && has_commitment_check {
                    let has_ordering_protection = window.iter().any(|&b| b == 0x43); // NUMBER (block-based ordering)
                    let has_simultaneous_reveal = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    
                    if !has_ordering_protection && !has_simultaneous_reveal {
                        vulns.push(CommitRevealVulnerability {
                            pc,
                            vulnerability_type: "RevealFrontrunning".to_string(),
                            description: format!(
                                "Reveal verification at PC {} vulnerable to frontrunning. First to reveal exposes information, later \
                                revealers can adjust. Attack: wait for someone to reveal in mempool, frontrun with better value. \
                                Example: auction where highest bid wins - see first reveal, outbid by 1 wei. Missing: simultaneous \
                                reveal requirement, commit-reveal-reveal scheme, sealed-bid mechanism. All reveals should be collected \
                                before processing.",
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

    fn detect_commitment_binding_weakness(&self) -> Vec<CommitRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (commitment)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_value = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_value {
                    let has_salt = window.iter().filter(|&&b| b == 0x35).count() >= 2; // Multiple inputs
                    let has_user_binding = window.iter().any(|&b| b == 0x33); // CALLER
                    
                    if !has_salt || !has_user_binding {
                        vulns.push(CommitRevealVulnerability {
                            pc,
                            vulnerability_type: "CommitmentBindingWeakness".to_string(),
                            description: format!(
                                "Commitment hash at PC {} insufficiently binds user. Attack vectors: (1) without salt, small value space \
                                enables brute-force preimage search, (2) without user address binding, attacker can replay others' \
                                commitments. Missing: random salt/nonce in hash, user address in commitment, sufficient entropy. \
                                Commitment should be: keccak256(value, salt, msg.sender) to prevent attacks.",
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
