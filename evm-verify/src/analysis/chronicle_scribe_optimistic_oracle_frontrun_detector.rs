use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ChronicleScribeOptimisticOracleFrontrunDetector {
    bytecode: Vec<u8>,
}

impl ChronicleScribeOptimisticOracleFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_optimistic_oracle_frontrun() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Chronicle's optimistic oracle updates can be front-run allowing exploitation of price changes during challenge period.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_challenge_period_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Challenge period can be manipulated to delay price corrections.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_optimistic_oracle_frontrun(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (oracle value)
                let mut has_challenge_check = false;
                let mut has_value_use = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x42 { // TIMESTAMP (challenge period)
                        has_challenge_check = true;
                    }
                    if bytecode[j] == 0xF1 && !has_challenge_check { // CALL without challenge check
                        has_value_use = true;
                    }
                }

                if has_value_use && !has_challenge_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_challenge_period_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ADD (extend period)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (update challenge deadline)
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
