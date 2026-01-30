/// Token Unlock Schedule Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct TokenUnlockScheduleBypassDetector {
    bytecode: Vec<u8>,
}

impl TokenUnlockScheduleBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_linear_unlock_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Linear unlock calculation vulnerable to overflow/manipulation at PC {}", pc),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_linear_unlock_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x1b | 0x2c) {
                    let mut has_time_calculation = false;
                    let mut has_overflow_check = false;

                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 { // DIV (time-based calculation)
                            has_time_calculation = true;
                        }
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT bounds
                            has_overflow_check = true;
                        }
                    }

                    if has_time_calculation && !has_overflow_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
