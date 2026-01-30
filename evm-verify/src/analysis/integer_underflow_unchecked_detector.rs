/// Integer Underflow Unchecked Detector
use crate::bytecode::SecurityFinding;

pub struct IntegerUnderflowUncheckedDetector {
    bytecode: Vec<u8>,
}

impl IntegerUnderflowUncheckedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Unchecked integer underflow detected at PC {}", location),
                pc: location,
                confidence: 0.94,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.check_unchecked_sub(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_unchecked_sub(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for SUB without underflow check
        if self.bytecode[pos] == 0x03 { // SUB
            if pos + 20 < self.bytecode.len() {
                // Look for underflow protection (GT or LT check before SUB)
                let mut has_check = false;
                
                // Check before SUB
                if pos > 10 {
                    for j in pos.saturating_sub(10)..pos {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT
                            has_check = true;
                            break;
                        }
                    }
                }
                
                // Check after SUB
                for j in (pos + 1)..(pos + 15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                        has_check = true;
                        break;
                    }
                }
                
                return !has_check;
            }
        }
        false
    }
}
