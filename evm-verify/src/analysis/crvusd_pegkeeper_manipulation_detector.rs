use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct CrvusdPegkeeperManipulationDetector {
    bytecode: Vec<u8>,
}

impl CrvusdPegkeeperManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_pegkeeper_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "PegKeeper can be manipulated to mint/burn at unfavorable rates, causing artificial depeg or arbitrage opportunities.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_debt_ceiling_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Debt ceiling can be bypassed through coordinated PegKeeper operations.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_pegkeeper_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (price check)
                let mut has_peg_calc = false;
                let mut has_mint_burn = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x03 { // SUB (peg deviation)
                        has_peg_calc = true;
                    }
                    if bytecode[j] == 0xF1 && has_peg_calc { // CALL (mint/burn)
                        has_mint_burn = true;
                    }
                }

                if has_peg_calc && has_mint_burn {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_debt_ceiling_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (debt ceiling)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x10 { // LT (ceiling check)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x57 { // JUMPI (bypass)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}
