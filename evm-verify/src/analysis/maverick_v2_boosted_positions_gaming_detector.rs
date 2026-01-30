use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct MaverickV2BoostedPositionsGamingDetector {
    bytecode: Vec<u8>,
}

impl MaverickV2BoostedPositionsGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_boosted_position_gaming() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Boosted liquidity positions can be gamed to extract disproportionate rewards without providing real liquidity.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_dynamic_bin_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Dynamic fee bins can be manipulated to avoid optimal fee collection.".to_string(),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_boosted_position_gaming(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (boost multiplier)
                let mut has_boost_calc = false;
                let mut has_reward = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (apply boost)
                        has_boost_calc = true;
                    }
                    if bytecode[j] == 0xF1 && has_boost_calc { // CALL (claim reward)
                        has_reward = true;
                    }
                }

                if has_boost_calc && has_reward {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_dynamic_bin_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (bin state)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (fee calculation)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (update bin)
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
