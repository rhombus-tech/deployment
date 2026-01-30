use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct OndoUsdyNavOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl OndoUsdyNavOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_nav_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Net Asset Value (NAV) oracle can be manipulated to cause mispricing of USDY tokens, affecting redemptions and minting.".to_string(),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_redemption_timing_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Redemptions can be timed to exploit NAV updates for arbitrage.".to_string(),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_nav_oracle_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (NAV oracle)
                let mut has_nav_calc = false;
                let mut has_price_update = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (NAV calculation)
                        has_nav_calc = true;
                    }
                    if bytecode[j] == 0x55 && has_nav_calc { // SSTORE (update price)
                        has_price_update = true;
                    }
                }

                if has_nav_calc && has_price_update {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_redemption_timing_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x54 { // SLOAD (NAV)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xF1 { // CALL (redeem)
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
