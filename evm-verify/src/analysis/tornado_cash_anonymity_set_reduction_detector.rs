/// Tornado Cash Anonymity Set Reduction Detector
use crate::bytecode::SecurityFinding;
pub struct TornadoCashAnonymitySetReductionDetector { bytecode: Vec<u8> }
impl TornadoCashAnonymitySetReductionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_small_anonymity_set() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Privacy pool deposit/withdraw pattern reduces anonymity at PC {}", pc),
                pc, confidence: 0.85
            });
        }
        findings
    }
    fn detect_small_anonymity_set(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x0a | 0x1b) { // deposit/withdraw
                    let mut has_delay = false;
                    for j in i..i+30.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j+5 < self.bytecode.len() {
                            if self.bytecode[j+4] == 0x01 { has_delay = true; }
                        }
                    }
                    if !has_delay { return Some(i); }
                }
            }
        }
        None
    }
}
