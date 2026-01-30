/// Yield Enhancement Product Detector
/// Ribbon Finance, Katana, Opyn covered call strategies
use crate::bytecode::SecurityFinding;

pub struct YieldEnhancementProductDetector { bytecode: Vec<u8> }

impl YieldEnhancementProductDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_strike_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Option strike price manipulable via single oracle at PC {}", pc),
                pc, confidence: 0.85
            });
        }
        findings
    }
    
    fn detect_strike_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x8c | 0x9d) {
                    let mut oracle_calls = 0;
                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { oracle_calls += 1; }
                    }
                    if oracle_calls < 2 { return Some(i); }
                }
            }
        }
        None
    }
}
