use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct FxProtocolLeverageStablecoinDepegDetector {
    bytecode: Vec<u8>,
}

impl FxProtocolLeverageStablecoinDepegDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_leverage_amplification_depeg() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Leveraged stablecoin positions can amplify depegs through cascading liquidations and collateral devaluation.".to_string(),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_leverage_ratio_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Leverage ratios can be manipulated to maintain undercollateralized positions or force liquidations.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_leverage_amplification_depeg(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0xFA { // STATICCALL (collateral price)
                let mut has_leverage_calc = false;
                let mut has_liquidation = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (leverage multiplier)
                        has_leverage_calc = true;
                    }
                    if bytecode[j] == 0x10 && has_leverage_calc { // LT (liquidation threshold)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xF1 { // CALL (liquidate)
                                has_liquidation = true;
                            }
                        }
                    }
                }

                if has_leverage_calc && has_liquidation {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_leverage_ratio_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (position)
                let mut has_ratio_calc = false;
                let mut has_update = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (leverage ratio)
                        has_ratio_calc = true;
                    }
                    if bytecode[j] == 0x55 && has_ratio_calc { // SSTORE (update)
                        has_update = true;
                    }
                }

                if has_ratio_calc && has_update {
                    return Some(i);
                }
            }
        }

        None
    }
}
