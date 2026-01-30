use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowReleaseVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct EscrowReleaseConditionBypassDetector {
    bytecode: Vec<u8>,
}

impl EscrowReleaseConditionBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EscrowReleaseVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_oracle_manipulation_release());
        vulnerabilities.extend(self.detect_partial_release_griefing());
        vulnerabilities.extend(self.detect_dispute_resolution_bypass());

        vulnerabilities
    }

    fn detect_oracle_manipulation_release(&self) -> Vec<EscrowReleaseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xFA | 0xF1) { // Oracle call for escrow condition
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_escrow_data = window.iter().any(|&b| b == 0x54); // SLOAD (escrow state)
                
                if has_escrow_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_release = forward.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL or SSTORE (releasing funds)
                    
                    if has_release {
                        let has_multiple_oracles = window.iter().filter(|&&b| matches!(b, 0xFA | 0xF1)).count() >= 2;
                        let has_dispute_period = forward.iter().any(|&b| b == 0x42); // TIMESTAMP
                        
                        if !has_multiple_oracles || !has_dispute_period {
                            vulns.push(EscrowReleaseVulnerability {
                                pc,
                                vulnerability_type: "OracleManipulationRelease".to_string(),
                                description: format!(
                                    "Escrow release at PC {} depends on single oracle. Compromised oracle can trigger unauthorized release. \
                                    Attack: bribe/hack oracle to report condition met, release escrowed funds prematurely. Missing: multiple \
                                    independent oracles, dispute period for challenge, manual override by arbiter. Escrow should not trust \
                                    single data source for high-value releases.",
                                    pc
                                ),
                                confidence: 0.88,
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

    fn detect_partial_release_griefing(&self) -> Vec<EscrowReleaseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (escrow release)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_amount = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (partial amount)
                let has_escrow_balance = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                
                if has_amount && has_escrow_balance {
                    let has_minimum_release = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_completion_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_minimum_release || !has_completion_check {
                        vulns.push(EscrowReleaseVulnerability {
                            pc,
                            vulnerability_type: "PartialReleaseGriefing".to_string(),
                            description: format!(
                                "Partial escrow release at PC {} without limits. Attack: release escrow in tiny amounts (1 wei each) to \
                                grief recipient with gas costs or spam. Each release costs recipient gas to process. Missing: minimum \
                                release amount, maximum release frequency, atomic full release option. Should prevent economic griefing \
                                through micro-releases.",
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

    fn detect_dispute_resolution_bypass(&self) -> Vec<EscrowReleaseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (resolving dispute)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_dispute_flag = window.iter().any(|&b| b == 0x54); // SLOAD (dispute state)
                let has_arbiter = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_dispute_flag && has_arbiter {
                    let has_evidence_verification = window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_time_limit = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_appeal_mechanism = window.iter().filter(|&&b| b == 0x57).count() >= 2;
                    
                    if !has_evidence_verification || !has_time_limit || !has_appeal_mechanism {
                        vulns.push(EscrowReleaseVulnerability {
                            pc,
                            vulnerability_type: "DisputeResolutionBypass".to_string(),
                            description: format!(
                                "Dispute resolution at PC {} trusts arbiter without verification. Malicious/compromised arbiter can \
                                release funds to wrong party. Attack: bribe arbiter to rule in favor regardless of evidence. Missing: \
                                evidence hash verification, multi-arbiter consensus, appeal period, time limits preventing indefinite \
                                disputes. Dispute resolution should have checks and balances.",
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
}
