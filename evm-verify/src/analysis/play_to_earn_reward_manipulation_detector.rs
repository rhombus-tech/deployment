/// Play-to-Earn Reward Manipulation Detector
use crate::bytecode::SecurityFinding;
pub struct PlayToEarnRewardManipulationDetector { bytecode: Vec<u8> }
impl PlayToEarnRewardManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_reward_rate_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Reward distribution rate modifiable without timelock at PC {}", pc),
                pc, confidence: 0.86
            });
        }
        findings
    }
    fn detect_reward_rate_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xb2 | 0xc3) { // setRewardRate
                    let mut has_timelock = false;
                    for j in i..i+30.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j+8 < self.bytecode.len() {
                            if self.bytecode[j+6] == 0x10 { has_timelock = true; }
                        }
                    }
                    if !has_timelock { return Some(i); }
                }
            }
        }
        None
    }
}
