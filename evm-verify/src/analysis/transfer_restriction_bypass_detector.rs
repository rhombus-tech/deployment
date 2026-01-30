/// Transfer Restriction Bypass Detector
use crate::bytecode::SecurityFinding;
pub struct TransferRestrictionBypassDetector { bytecode: Vec<u8> }
impl TransferRestrictionBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_lockup_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Token lockup period bypassable via delegated transfer at PC {}", pc),
                pc, confidence: 0.87
            });
        }
        findings
    }
    fn detect_lockup_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x23 | 0xa9) { // transferFrom, transfer
                    let mut has_lockup = false;
                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j+5 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j+4] == 0x11 { has_lockup = true; } // GT
                        }
                    }
                    if !has_lockup { return Some(i); }
                }
            }
        }
        None
    }
}
