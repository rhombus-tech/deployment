use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct VertexProtocolCrossMarginManipulationDetector {
    bytecode: Vec<u8>,
}

impl VertexProtocolCrossMarginManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_cross_margin_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Cross-margin positions can be manipulated to avoid liquidation or extract collateral through multi-market exploits.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_portfolio_margin_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Portfolio margin calculations can be gamed to maintain undercollateralized positions.".to_string(),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_cross_margin_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut margin_checks = 0;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (position)
                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { // LT/GT (margin check)
                        margin_checks += 1;
                        if margin_checks >= 2 {
                            for k in j+1..std::cmp::min(j+20, bytecode.len()) {
                                if bytecode[k] == 0xF1 { // CALL (liquidation)
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_portfolio_margin_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0xFA { // STATICCALL (price oracle)
                let mut has_multi_asset = false;
                let mut has_margin_calc = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ADD (combine positions)
                        has_multi_asset = true;
                    }
                    if bytecode[j] == 0x04 && has_multi_asset { // DIV (margin ratio)
                        has_margin_calc = true;
                    }
                }

                if has_multi_asset && has_margin_calc {
                    return Some(i);
                }
            }
        }

        None
    }
}
