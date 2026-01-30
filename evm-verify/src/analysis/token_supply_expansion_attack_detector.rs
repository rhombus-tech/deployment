use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyExpansionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TokenSupplyExpansionAttackDetector {
    bytecode: Vec<u8>,
}

impl TokenSupplyExpansionAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SupplyExpansionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_minting());
        vulnerabilities.extend(self.detect_supply_cap_bypass());
        vulnerabilities.extend(self.detect_inflation_rate_manipulation());

        vulnerabilities
    }

    fn detect_unbounded_minting(&self) -> Vec<SupplyExpansionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ADD (balance increase)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_balance_write = {
                    let window_end = (pc + 40).min(self.bytecode.len());
                    self.bytecode[pc..window_end].iter().any(|&b| b == 0x55)
                };
                
                if has_balance_write {
                    let has_cap_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_total_supply_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_cap_check && !has_total_supply_check {
                        vulns.push(SupplyExpansionVulnerability {
                            pc,
                            vulnerability_type: "UnboundedMinting".to_string(),
                            description: format!(
                                "Token minting at PC {} without supply cap validation. Privileged minter can inflate \
                                supply indefinitely, devaluing existing holders. Missing: maximum supply enforcement, \
                                total supply tracking, minting rate limits. Enables hyperinflation attack destroying \
                                token value.",
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

    fn detect_supply_cap_bypass(&self) -> Vec<SupplyExpansionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x10 || opcode == 0x11 { // LT, GT (cap check)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_total_supply = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_total_supply {
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_overflow_protection = forward_window.iter().any(|&b| b == 0xFD);
                    let has_safe_math = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() > 2;
                    
                    if !has_overflow_protection && !has_safe_math {
                        vulns.push(SupplyExpansionVulnerability {
                            pc,
                            vulnerability_type: "SupplyCapBypass".to_string(),
                            description: format!(
                                "Supply cap check at PC {} vulnerable to integer overflow bypass. Attacker mints amount \
                                causing totalSupply to overflow, wrapping to small value, bypassing cap. Missing: overflow \
                                protection, safe arithmetic, pre-mint validation. Enables unlimited minting despite cap.",
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

    fn detect_inflation_rate_manipulation(&self) -> Vec<SupplyExpansionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (time-based inflation)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_mul = window.iter().any(|&b| b == 0x02); // MUL (rate calculation)
                let has_add = window.iter().any(|&b| b == 0x01); // ADD (supply increase)
                
                if has_mul && has_add {
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_rate_governance = pre_window.iter().any(|&b| b == 0x33); // CALLER check
                    let has_rate_cap = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_rate_governance && !has_rate_cap {
                        vulns.push(SupplyExpansionVulnerability {
                            pc,
                            vulnerability_type: "InflationRateManipulation".to_string(),
                            description: format!(
                                "Time-based inflation at PC {} with unconstrained rate parameter. Admin can arbitrarily \
                                increase inflation rate, rapidly devaluing token. Missing: rate change governance timelock, \
                                maximum rate bounds, gradual adjustment mechanism. Enables rugpull via sudden hyperinflation.",
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
}
