/// Validator Exit Griefing Detector
use crate::bytecode::SecurityFinding;
pub struct ValidatorExitGriefingDetector { bytecode: Vec<u8> }
impl ValidatorExitGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_exit_delay_griefing() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Validator exit lacks maximum delay cap, griefing possible at PC {}", pc),
                pc, confidence: 0.85
            });
        }
        findings
    }
    fn detect_exit_delay_griefing(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xf2 | 0xa3) {
                    let mut has_max_delay = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 { has_max_delay = true; }
                    }
                    if !has_max_delay { return Some(i); }
                }
            }
        }
        None
    }
}
