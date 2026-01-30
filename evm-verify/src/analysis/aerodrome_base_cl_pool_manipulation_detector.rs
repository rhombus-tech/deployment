use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct AerodromeBaseClPoolManipulationDetector {
    bytecode: Vec<u8>,
}

impl AerodromeBaseClPoolManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_concentrated_liquidity_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Concentrated liquidity pools on Base can be manipulated through tick spacing exploits or oracle manipulation.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_vote_incentive_gaming() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Vote-escrowed governance can be gamed to direct incentives unfairly.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_concentrated_liquidity_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (tick)
                let mut has_liquidity_change = false;
                let mut has_swap = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x01 || bytecode[j] == 0x03 { // ADD/SUB (liquidity)
                        has_liquidity_change = true;
                    }
                    if bytecode[j] == 0xF1 && has_liquidity_change { // CALL (swap)
                        has_swap = true;
                    }
                }

                if has_liquidity_change && has_swap {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_vote_incentive_gaming(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (voting power)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (incentive calculation)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xF1 { // CALL (claim)
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
