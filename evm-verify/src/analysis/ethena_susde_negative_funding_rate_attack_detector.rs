use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct EthenaSusdeNegativeFundingRateAttackDetector {
    bytecode: Vec<u8>,
}

impl EthenaSusdeNegativeFundingRateAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_negative_funding_rate_attack() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Sustained negative funding rates can cause sUSDe depeg and force liquidations due to decreasing collateral value.".to_string(),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_yield_mechanism_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Yield distribution mechanism can be exploited through strategic deposits/withdrawals during funding rate changes.".to_string(),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_negative_funding_rate_attack(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (funding rate oracle)
                let mut has_rate_check = false;
                let mut has_collateral_update = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x13 { // SGT (check if negative)
                        has_rate_check = true;
                    }
                    if bytecode[j] == 0x55 && has_rate_check { // SSTORE (update value)
                        has_collateral_update = true;
                    }
                }

                if has_rate_check && has_collateral_update {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_yield_mechanism_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (yield accumulator)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (yield calculation)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xF1 { // CALL (transfer)
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
