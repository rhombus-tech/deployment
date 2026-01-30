/// Toxic Flow Detection - Informed Order Flow
use crate::bytecode::SecurityFinding;

pub struct ToxicFlowDetector {
    bytecode: Vec<u8>,
}

impl ToxicFlowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Toxic flow vulnerability at PC {}", location),
                pc: location,
                confidence: 0.78,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.check_toxic_flow(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_toxic_flow(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for large trades without trade size limits
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // swap functions
            if matches!(self.bytecode[pos+1], 0x38 | 0xfb) {
                let mut has_size_limit = false;
                
                if pos + 40 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        // Check for max trade size comparison
                        if matches!(self.bytecode[j], 0x10 | 0x11) && j + 3 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_size_limit = true;
                                break;
                            }
                        }
                    }
                }
                return !has_size_limit;
            }
        }
        false
    }
}
