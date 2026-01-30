/// Integer Overflow Unchecked Detector
use crate::bytecode::SecurityFinding;

pub struct IntegerOverflowUncheckedDetector {
    bytecode: Vec<u8>,
}

impl IntegerOverflowUncheckedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Unchecked integer overflow detected at PC {}", location),
                pc: location,
                confidence: 0.94,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.check_unchecked_add_mul(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_unchecked_add_mul(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for ADD or MUL without overflow check
        if matches!(self.bytecode[pos], 0x01 | 0x02) {
            if pos + 20 < self.bytecode.len() {
                // Look for overflow checks (LT, GT comparisons or REVERT)
                let mut has_check = false;
                for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x12) { // LT, GT, SLT
                        if j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0xfd | 0x57) { // REVERT or JUMPI
                                has_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_check;
            }
        }
        false
    }
}
