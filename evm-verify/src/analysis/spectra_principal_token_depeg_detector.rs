use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SpectraPrincipalTokenDepegDetector {
    bytecode: Vec<u8>,
}

impl SpectraPrincipalTokenDepegDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_principal_token_depeg_risk() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Principal token (PT) can depeg from underlying due to yield rate manipulation or liquidity attacks, causing losses for PT holders.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_yield_stripping_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Yield can be stripped from principal tokens through timestamp manipulation or early redemption exploits.".to_string(),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_principal_token_depeg_risk(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (oracle/price check)
                let mut has_pt_calculation = false;
                let mut has_swap = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 || bytecode[j] == 0x02 {
                        has_pt_calculation = true;
                    }
                    if bytecode[j] == 0xF1 && has_pt_calculation {
                        has_swap = true;
                    }
                }

                if has_pt_calculation && has_swap {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_yield_stripping_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { // LT/GT
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (yield update)
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
