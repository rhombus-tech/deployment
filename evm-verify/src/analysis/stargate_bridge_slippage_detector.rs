/// Stargate Bridge Slippage Detector
use crate::bytecode::SecurityFinding;

pub struct StargateBridgeSlippageDetector {
    bytecode: Vec<u8>,
}

impl StargateBridgeSlippageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Stargate bridge slippage vulnerability at PC {}", location),
                pc: location,
                confidence: 0.80,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.check_slippage_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_slippage_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for swap without amountOutMin validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if (self.bytecode[pos+1] == 0x48 || self.bytecode[pos+1] == 0x01) {
                let mut has_min_amount_check = false;
                if pos + 30 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        // Look for LT comparison for minimum amount
                        if self.bytecode[j] == 0x10 && j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0x57 | 0xfd) {
                                has_min_amount_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_min_amount_check;
            }
        }
        false
    }
}
