/// Options Expiry Pinning Detector
use crate::bytecode::SecurityFinding;

pub struct OptionsExpiryPinningDetector {
    bytecode: Vec<u8>,
}

impl OptionsExpiryPinningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_settlement_price_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Option settlement price vulnerable to pinning attack at PC {}", pc),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_settlement_price_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xc3 | 0xd4) { // settle, expire
                    let mut has_twap = false;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j+10 < self.bytecode.len() {
                            if self.bytecode[j+8] == 0x04 { // DIV (avg calculation)
                                has_twap = true;
                            }
                        }
                    }
                    if !has_twap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
