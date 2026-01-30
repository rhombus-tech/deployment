use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct AevoOptionsPerpIvManipulationDetector {
    bytecode: Vec<u8>,
}

impl AevoOptionsPerpIvManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_implied_volatility_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Implied volatility calculations can be manipulated through wash trading or oracle attacks, causing mispriced options.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_option_perp_basis_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Price discrepancies between options and perpetuals can be exploited for risk-free arbitrage.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_implied_volatility_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (IV oracle)
                let mut has_vol_calc = false;
                let mut has_price_update = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x0A { // EXP (Black-Scholes)
                        has_vol_calc = true;
                    }
                    if bytecode[j] == 0x55 && has_vol_calc { // SSTORE
                        has_price_update = true;
                    }
                }

                if has_vol_calc && has_price_update {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_option_perp_basis_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0xF1 { // CALL (option trade)
                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL (perp trade)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x03 { // SUB (basis calculation)
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
