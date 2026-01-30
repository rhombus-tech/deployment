use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct HyperliquidityVammLiquidationCascadeDetector {
    bytecode: Vec<u8>,
}

impl HyperliquidityVammLiquidationCascadeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_vamm_liquidation_cascade() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Virtual AMM liquidations can trigger cascading failures as price impact causes further liquidations in a feedback loop.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_oracle_vamm_divergence() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Divergence between oracle price and vAMM price can be exploited for liquidation manipulation.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_vamm_liquidation_cascade(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x54 { // SLOAD (position)
                let mut has_price_impact = false;
                let mut has_liquidation = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (price calculation)
                        has_price_impact = true;
                    }
                    if bytecode[j] == 0x10 && has_price_impact { // LT (liquidation threshold)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xF1 { // CALL (liquidate)
                                has_liquidation = true;
                            }
                        }
                    }
                }

                if has_price_impact && has_liquidation {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_oracle_vamm_divergence(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (oracle)
                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x54 { // SLOAD (vAMM price)
                        for k in j+1..std::cmp::min(j+20, bytecode.len()) {
                            if bytecode[k] == 0x03 { // SUB (price difference)
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
