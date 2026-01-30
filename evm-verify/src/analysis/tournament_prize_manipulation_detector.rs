/// Tournament Prize Manipulation Detector
use crate::bytecode::SecurityFinding;
pub struct TournamentPrizeManipulationDetector { bytecode: Vec<u8> }
impl TournamentPrizeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_winner_override() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Tournament winners modifiable by admin without multisig at PC {}", pc),
                pc, confidence: 0.88
            });
        }
        findings
    }
    fn detect_winner_override(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xf6 | 0xa7) { // setWinner
                    let mut has_multisig = false;
                    for j in i..i+30.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { has_multisig = true; } // External call to multisig
                    }
                    if !has_multisig { return Some(i); }
                }
            }
        }
        None
    }
}
