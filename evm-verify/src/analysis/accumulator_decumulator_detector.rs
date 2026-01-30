/// Accumulator/Decumulator Detector
use crate::bytecode::SecurityFinding;
pub struct AccumulatorDecumulatorDetector { bytecode: Vec<u8> }
impl AccumulatorDecumulatorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_knockout_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Accumulator knockout level determined by single oracle at PC {}", pc),
                pc, confidence: 0.85
            });
        }
        if let Some(pc) = self.detect_leverage_overflow() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Accumulator leverage multiplication lacks overflow protection at PC {}", pc),
                pc, confidence: 0.90
            });
        }
        findings
    }
    fn detect_knockout_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xde | 0xef) {
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
    fn detect_leverage_overflow(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xfa | 0xfb) {
                    let mut has_mul = false;
                    let mut has_overflow_check = false;
                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 { has_mul = true; } // MUL
                        if has_mul && (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) {
                            has_overflow_check = true;
                        }
                    }
                    if has_mul && !has_overflow_check { return Some(i); }
                }
            }
        }
        None
    }
}
