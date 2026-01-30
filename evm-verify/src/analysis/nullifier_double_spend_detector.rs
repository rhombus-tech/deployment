/// Nullifier Double Spend Detector
use crate::bytecode::SecurityFinding;
pub struct NullifierDoubleSpendDetector { bytecode: Vec<u8> }
impl NullifierDoubleSpendDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_missing_nullifier_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Nullifier reuse not prevented, double-spend possible at PC {}", pc),
                pc, confidence: 0.92
            });
        }
        findings
    }
    fn detect_missing_nullifier_check(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x2e | 0x3f) {
                    let mut has_nullifier = false;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j+5 < self.bytecode.len() {
                            if self.bytecode[j+4] == 0x15 { has_nullifier = true; }
                        }
                    }
                    if !has_nullifier { return Some(i); }
                }
            }
        }
        None
    }
}
