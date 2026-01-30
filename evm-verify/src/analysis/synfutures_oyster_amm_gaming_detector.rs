use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SynfuturesOysterAmmGamingDetector {
    bytecode: Vec<u8>,
}

impl SynfuturesOysterAmmGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_oyster_amm_gaming() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Oyster AMM's dynamic fee mechanism can be gamed through coordinated trades to manipulate funding rates or liquidity.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_funding_rate_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Funding rate calculations can be manipulated through large position changes near settlement.".to_string(),
                pc,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_oyster_amm_gaming(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (pool state)
                let mut has_fee_calc = false;
                let mut has_liquidity_change = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (fee calculation)
                        has_fee_calc = true;
                    }
                    if bytecode[j] == 0x55 && has_fee_calc { // SSTORE (update)
                        has_liquidity_change = true;
                    }
                }

                if has_fee_calc && has_liquidity_change {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_funding_rate_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x06 { // MOD (funding period)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (funding rate update)
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
