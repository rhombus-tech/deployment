/// Hop Bridge Bonder Detector
use crate::bytecode::SecurityFinding;

pub struct HopBridgeBonderDetector {
    bytecode: Vec<u8>,
}

impl HopBridgeBonderDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Hop Bridge bonder validation bypass at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_bonder_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_bonder_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for stake/bondWithdrawal without bonder signature verification
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if (self.bytecode[pos+1] == 0x32 || self.bytecode[pos+1] == 0xa9) {
                let mut has_signature_check = false;
                if pos + 35 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        // Look for ecrecover (0x01 precompile CALL)
                        if self.bytecode[j] == 0xf1 && j > 5 {
                            if self.bytecode[j-5] == 0x60 && self.bytecode[j-4] == 0x01 {
                                has_signature_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_signature_check;
            }
        }
        false
    }
}
