/// Dual Currency Product Detector
use crate::bytecode::SecurityFinding;
pub struct DualCurrencyProductDetector { bytecode: Vec<u8> }
impl DualCurrencyProductDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_fx_rate_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("FX rate for dual currency determined by single oracle at PC {}", pc),
                pc, confidence: 0.86
            });
        }
        findings
    }
    fn detect_fx_rate_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if self.bytecode[i+1] == 0xcd {
                    let mut oracles = 0;
                    for j in i..i+30.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { oracles += 1; }
                    }
                    if oracles < 2 { return Some(i); }
                }
            }
        }
        None
    }
}
