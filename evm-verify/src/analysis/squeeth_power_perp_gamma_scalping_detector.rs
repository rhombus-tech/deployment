use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SqueethPowerPerpGammaScalpingDetector {
    bytecode: Vec<u8>,
}

impl SqueethPowerPerpGammaScalpingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_gamma_scalping_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Power perpetual positions can be exploited through gamma scalping during high volatility to extract value from LPs.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_funding_rate_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Funding rate calculations can be manipulated to favor certain positions.".to_string(),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_gamma_scalping_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x54 { // SLOAD (position)
                let mut has_power_calc = false;
                let mut has_repeated_trades = false;
                let mut trade_count = 0;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x0A { // EXP (power calculation)
                        has_power_calc = true;
                    }
                    if bytecode[j] == 0xF1 && has_power_calc { // CALL (trade)
                        trade_count += 1;
                        if trade_count >= 2 {
                            has_repeated_trades = true;
                        }
                    }
                }

                if has_power_calc && has_repeated_trades {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_funding_rate_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x42 { // TIMESTAMP (funding period)
                let mut has_rate_calc = false;
                let mut has_update = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (funding rate)
                        has_rate_calc = true;
                    }
                    if bytecode[j] == 0x55 && has_rate_calc { // SSTORE
                        has_update = true;
                    }
                }

                if has_rate_calc && has_update {
                    return Some(i);
                }
            }
        }

        None
    }
}
