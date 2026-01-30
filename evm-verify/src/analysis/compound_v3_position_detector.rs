/// Compound V3 Position Detector
use crate::bytecode::SecurityFinding;
pub struct CompoundV3PositionDetector { bytecode: Vec<u8> }
impl CompoundV3PositionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if self.bytecode[i+1] == 0xd6 && self.bytecode[i+2] == 0x5f {
                    for j in (i+5)..(i+25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { return vec![SecurityFinding {
                            severity: crate::bytecode::SecuritySeverity::Medium,
                            description: format!("Compound V3 position risk at PC {}", i),
                            pc: i, confidence: 0.80,
                        }]; }
                    }
                }
            }
        }
        Vec::new()
    }
}
