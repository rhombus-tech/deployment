/// Consensus Layer Withdrawal Delay Detector
use crate::bytecode::SecurityFinding;
pub struct ConsensusLayerWithdrawalDelayDetector { bytecode: Vec<u8> }
impl ConsensusLayerWithdrawalDelayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_unbounded_withdrawal_delay() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Withdrawal delay lacks maximum bound at PC {}", pc),
                pc, confidence: 0.83
            });
        }
        findings
    }
    fn detect_unbounded_withdrawal_delay(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xf8 | 0xa9) {
                    let mut has_max = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 { has_max = true; }
                    }
                    if !has_max { return Some(i); }
                }
            }
        }
        None
    }
}
