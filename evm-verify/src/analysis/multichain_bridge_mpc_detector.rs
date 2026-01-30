/// Multichain Bridge MPC Detector
use crate::bytecode::SecurityFinding;

pub struct MultichainBridgeMpcDetector {
    bytecode: Vec<u8>,
}

impl MultichainBridgeMpcDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Multichain MPC key compromise vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_mpc_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_mpc_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for anySwap/execute without threshold signature verification
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if (self.bytecode[pos+1] == 0x82 || self.bytecode[pos+1] == 0x61) {
                let mut has_threshold_check = false;
                if pos + 35 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        // Look for signature count validation (LT/GT comparison)
                        if matches!(self.bytecode[j], 0x10 | 0x11) && j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0x57 | 0xfd) {
                                has_threshold_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_threshold_check;
            }
        }
        false
    }
}
