/// Liquid Staking Depeg Detector
use crate::bytecode::SecurityFinding;
pub struct LiquidStakingDepegDetector { bytecode: Vec<u8> }
impl LiquidStakingDepegDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_peg_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Liquid staking token peg uses single oracle at PC {}", pc),
                pc, confidence: 0.86
            });
        }
        findings
    }
    fn detect_peg_oracle_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xd6 | 0xe7) {
                    let mut oracle_count = 0;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { oracle_count += 1; }
                    }
                    if oracle_count < 2 { return Some(i); }
                }
            }
        }
        None
    }
}
