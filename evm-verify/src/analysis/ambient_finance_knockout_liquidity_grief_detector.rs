use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct AmbientFinanceKnockoutLiquidityGriefDetector {
    bytecode: Vec<u8>,
}

impl AmbientFinanceKnockoutLiquidityGriefDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_knockout_liquidity_griefing() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Knockout liquidity can be griefed through strategic price manipulation causing premature trigger of knockout conditions.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_concentrated_position_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Concentrated liquidity positions can be manipulated to extract value from LPs.".to_string(),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_knockout_liquidity_griefing(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (tick position)
                let mut has_price_check = false;
                let mut has_knockout = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { // LT/GT (price threshold)
                        has_price_check = true;
                    }
                    if bytecode[j] == 0x55 && has_price_check { // SSTORE (trigger knockout)
                        has_knockout = true;
                    }
                }

                if has_price_check && has_knockout {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_concentrated_position_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x02 { // MUL (liquidity calculation)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (fee distribution)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (update position)
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
