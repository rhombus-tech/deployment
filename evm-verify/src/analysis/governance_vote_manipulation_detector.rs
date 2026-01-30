/// Governance Vote Manipulation Detector  
use crate::bytecode::SecurityFinding;
pub struct GovernanceVoteManipulationDetector { bytecode: Vec<u8> }
impl GovernanceVoteManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if self.bytecode[i+1] == 0x15 && self.bytecode[i+2] == 0x37 { // castVote selector
                    for j in (i+5)..(i+25) {
                        if self.bytecode[j] == 0x55 && j > 10 {
                            let mut has_snapshot_check = false;
                            for k in j.saturating_sub(10)..j {
                                if self.bytecode[k] == 0x43 { has_snapshot_check = true; break; } // TIMESTAMP/NUMBER
                            }
                            if !has_snapshot_check { return vec![SecurityFinding {
                                severity: crate::bytecode::SecuritySeverity::High,
                                description: format!("Governance snapshot bypass at PC {}", i),
                                pc: i, confidence: 0.84,
                            }]; }
                        }
                    }
                }
            }
        }
        Vec::new()
    }
}
