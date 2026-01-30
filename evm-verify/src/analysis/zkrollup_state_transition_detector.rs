/// ZK Rollup State Transition Detector
use crate::bytecode::SecurityFinding;
pub struct ZkrollupStateTransitionDetector { bytecode: Vec<u8> }
impl ZkrollupStateTransitionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 && i > 20 { // SSTORE
                let mut has_proof_check = false;
                for j in i.saturating_sub(20)..i {
                    if matches!(self.bytecode[j], 0xfa | 0xf1) { has_proof_check = true; break; }
                }
                if !has_proof_check { return vec![SecurityFinding {
                    severity: crate::bytecode::SecuritySeverity::Critical,
                    description: format!("ZK state transition without proof at PC {}", i),
                    pc: i, confidence: 0.88,
                }]; }
            }
        }
        Vec::new()
    }
}
