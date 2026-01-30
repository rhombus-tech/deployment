/// Outcome Manipulation Before Resolution Detector
use crate::bytecode::SecurityFinding;
pub struct OutcomeManipulationBeforeResolutionDetector { bytecode: Vec<u8> }
impl OutcomeManipulationBeforeResolutionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_pre_resolution_trading() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Market allows trading after outcome known but before resolution at PC {}", pc),
                pc, confidence: 0.86
            });
        }
        findings
    }
    fn detect_pre_resolution_trading(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xa8 | 0xb9) {
                    let mut has_resolution_check = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j+5 < self.bytecode.len() {
                            if self.bytecode[j+4] == 0x15 { has_resolution_check = true; }
                        }
                    }
                    if !has_resolution_check { return Some(i); }
                }
            }
        }
        None
    }
}
