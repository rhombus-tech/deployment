use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct PolynomialVaultCoveredCallEarlyExerciseDetector {
    bytecode: Vec<u8>,
}

impl PolynomialVaultCoveredCallEarlyExerciseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_early_exercise_exploit() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Covered call options can be exercised early to exploit vault positions before proper settlement.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_strike_price_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Strike price calculations can be manipulated during option writing.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_early_exercise_exploit(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x42 { // TIMESTAMP (expiry check)
                let mut has_expiry_validation = false;
                let mut has_exercise = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x11 { // GT (check not expired)
                        has_expiry_validation = true;
                    }
                    if bytecode[j] == 0xF1 && !has_expiry_validation { // CALL (exercise without check)
                        has_exercise = true;
                    }
                }

                if has_exercise && !has_expiry_validation {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_strike_price_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0xFA { // STATICCALL (oracle price)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (strike calculation)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (set strike)
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
