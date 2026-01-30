use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialRecoveryVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SocialRecoveryCollusionDetector {
    bytecode: Vec<u8>,
}

impl SocialRecoveryCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_instant_recovery());
        vulnerabilities.extend(self.detect_unilateral_guardian_addition());
        vulnerabilities.extend(self.detect_immediate_execution());

        vulnerabilities
    }

    fn detect_instant_recovery(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x10 || opcode == 0x11 {
                let window_start = if pc > 50 { pc - 50 } else { 0 };
                let window_end = (pc + 80).min(self.bytecode.len());
                
                let has_sload = self.bytecode[window_start..window_end].iter().any(|&b| b == 0x54);
                let has_timelock = self.bytecode[window_start..window_end].iter().any(|&b| b == 0x42);
                let has_execution = self.bytecode[window_start..window_end].iter()
                    .any(|&b| b == 0xF1 || b == 0xF4 || b == 0x55);
                
                if has_sload && has_execution && !has_timelock {
                    vulns.push(SocialRecoveryVulnerability {
                        pc,
                        vulnerability_type: "InstantRecovery".to_string(),
                        description: format!(
                            "Guardian threshold at PC {} allows instant recovery. Colluding guardians can \
                            immediately transfer ownership. Implement 24-72 hour timelock.",
                            pc
                        ),
                        confidence: 0.80,
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

    fn detect_unilateral_guardian_addition(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_caller = self.bytecode[start..pc].iter().any(|&b| b == 0x33);
                let sload_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count();
                
                if has_caller && sload_count < 2 {
                    vulns.push(SocialRecoveryVulnerability {
                        pc,
                        vulnerability_type: "UnilateralGuardianAddition".to_string(),
                        description: format!(
                            "Guardian addition at PC {} without existing guardian approval. Owner can add \
                            colluding guardians. Require M-of-N guardian approval.",
                            pc
                        ),
                        confidence: 0.75,
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

    fn detect_immediate_execution(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0xF1 || opcode == 0xF4 {
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_threshold = self.bytecode[start..pc].iter().any(|&b| b == 0x10 || b == 0x11);
                let has_delay = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                
                if has_threshold && !has_delay {
                    vulns.push(SocialRecoveryVulnerability {
                        pc,
                        vulnerability_type: "ImmediateExecution".to_string(),
                        description: format!(
                            "Recovery execution at PC {} without timelock. Use two-step: propose with \
                            48-72 hour delay, then execute. Owner can cancel during delay.",
                            pc
                        ),
                        confidence: 0.85,
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
