/// Autocallable Barrier Manipulation Detector
use crate::bytecode::SecurityFinding;
pub struct AutocallableBarrierManipulationDetector { bytecode: Vec<u8> }
impl AutocallableBarrierManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_barrier_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Autocall barrier check uses single oracle at PC {}", pc),
                pc, confidence: 0.84
            });
        }
        findings
    }
    fn detect_barrier_oracle_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xae | 0xbf) {
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
