/// Slashing Condition Manipulation Detector
use crate::bytecode::SecurityFinding;
pub struct SlashingConditionManipulationDetector { bytecode: Vec<u8> }
impl SlashingConditionManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_slashing_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Slashing condition uses single oracle, manipulable at PC {}", pc),
                pc, confidence: 0.90
            });
        }
        findings
    }
    fn detect_slashing_oracle_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xd0 | 0xe1) {
                    let mut oracle_calls = 0;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { oracle_calls += 1; }
                    }
                    if oracle_calls < 2 { return Some(i); }
                }
            }
        }
        None
    }
}
