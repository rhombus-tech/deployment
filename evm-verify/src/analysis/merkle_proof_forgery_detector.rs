/// Merkle Proof Forgery Detector
use crate::bytecode::SecurityFinding;
pub struct MerkleProofForgeryDetector { bytecode: Vec<u8> }
impl MerkleProofForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 && i + 25 < self.bytecode.len() { // KECCAK256
                let mut has_length_check = false;
                for j in i.saturating_sub(10)..i {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { has_length_check = true; break; }
                }
                if !has_length_check && i + 15 < self.bytecode.len() {
                    for k in (i+1)..(i+15) {
                        if self.bytecode[k] == 0x14 { // EQ check
                            return vec![SecurityFinding {
                                severity: crate::bytecode::SecuritySeverity::High,
                                description: format!("Merkle proof without length validation at PC {}", i),
                                pc: i, confidence: 0.83,
                            }];
                        }
                    }
                }
            }
        }
        Vec::new()
    }
}
