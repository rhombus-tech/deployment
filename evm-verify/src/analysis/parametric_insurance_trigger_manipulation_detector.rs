/// Parametric Insurance Trigger Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct ParametricInsuranceTriggerManipulationDetector {
    bytecode: Vec<u8>,
}

impl ParametricInsuranceTriggerManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_trigger_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Insurance trigger uses single oracle, manipulable at PC {}", pc),
                pc,
                confidence: 0.91,
            });
        }

        findings
    }

    fn detect_trigger_oracle_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xc9 | 0xda) { // checkTrigger
                    let mut oracle_count = 0;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            oracle_count += 1;
                        }
                    }
                    if oracle_count < 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
