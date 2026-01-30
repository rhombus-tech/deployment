use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnDeflationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TokenBurnDeflationaryAttackDetector {
    bytecode: Vec<u8>,
}

impl TokenBurnDeflationaryAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BurnDeflationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_forced_burn_griefing());
        vulnerabilities.extend(self.detect_burn_rate_manipulation());
        vulnerabilities.extend(self.detect_supply_oracle_manipulation());

        vulnerabilities
    }

    fn detect_forced_burn_griefing(&self) -> Vec<BurnDeflationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x03 { // SUB (burn reducing balance)
                let window_end = (pc + 40).min(self.bytecode.len());
                let has_sstore = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                
                if has_sstore {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let window = &self.bytecode[start..pc];
                    
                    let has_caller_consent = window.iter().any(|&b| b == 0x33); // CALLER check
                    let has_amount_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_caller_consent && !has_amount_limit {
                        vulns.push(BurnDeflationVulnerability {
                            pc,
                            vulnerability_type: "ForcedBurnGriefing".to_string(),
                            description: format!(
                                "Token burn at PC {} allows burning others' tokens without consent. Admin or burner role \
                                can forcibly deflate supply by burning user tokens, griefing holders. Missing: token owner \
                                authorization, burn amount limits, opt-in mechanism. Enables targeted attacks destroying \
                                specific users' holdings.",
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

    fn detect_burn_rate_manipulation(&self) -> Vec<BurnDeflationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 || opcode == 0x04 { // MUL or DIV (burn fee calculation)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let window_end = (pc + 50).min(self.bytecode.len());
                let forward = &self.bytecode[pc..window_end];
                
                let has_burn = forward.iter().any(|&b| b == 0x03); // SUB (burning)
                
                if has_burn {
                    let has_rate_governance = window.iter().any(|&b| b == 0x33); // CALLER
                    let has_max_rate = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if has_rate_governance && !has_max_rate {
                        vulns.push(BurnDeflationVulnerability {
                            pc,
                            vulnerability_type: "BurnRateManipulation".to_string(),
                            description: format!(
                                "Burn rate calculation at PC {} with uncapped admin control. Privileged role can set burn \
                                fee to 100%, effectively stealing all transferred tokens. Missing: maximum burn rate cap, \
                                governance timelock, gradual rate changes. Enables rugpull via extreme deflationary mechanism.",
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

    fn detect_supply_oracle_manipulation(&self) -> Vec<BurnDeflationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (totalSupply)
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_external_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // CALL, STATICCALL
                
                if has_external_call {
                    let has_validation = window.iter().any(|&b| b == 0x14); // EQ
                    let has_sanity_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_validation && !has_sanity_check {
                        vulns.push(BurnDeflationVulnerability {
                            pc,
                            vulnerability_type: "SupplyOracleManipulation".to_string(),
                            description: format!(
                                "Supply data at PC {} used in oracle without validation. Burn mechanisms relying on \
                                reported supply can be manipulated. Attack: report artificially low supply to trigger \
                                excessive deflationary burns, or high supply to disable burns. Missing: supply bounds \
                                validation, multi-oracle consensus, sanity checks. Enables supply manipulation attacks.",
                                pc
                            ),
                            confidence: 0.82,
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
