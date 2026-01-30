/// Returndata Overflow Detector
use crate::bytecode::SecurityFinding;

pub struct ReturndataOverflowDetector {
    bytecode: Vec<u8>,
}

impl ReturndataOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Return data buffer overflow vulnerability at PC {}", location),
                pc: location,
                confidence: 0.92,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.check_returndata_copy(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_returndata_copy(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for RETURNDATASIZE followed by RETURNDATACOPY without bounds check
        if self.bytecode[pos] == 0x3d { // RETURNDATASIZE
            if pos + 15 < self.bytecode.len() {
                for j in (pos + 1)..(pos + 15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x3e { // RETURNDATACOPY
                        // Check if size is validated
                        let mut has_size_check = false;
                        for k in (pos + 1)..j {
                            if matches!(self.bytecode[k], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                                has_size_check = true;
                                break;
                            }
                        }
                        if !has_size_check {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}
