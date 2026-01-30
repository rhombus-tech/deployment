/// MakerDAO Liquidation Detector
use crate::bytecode::SecurityFinding;
pub struct MakerDaoLiquidationDetector { bytecode: Vec<u8> }
impl MakerDaoLiquidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 && self.bytecode[i+1] == 0x69 {
                for j in (i+5)..(i+20).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { continue; }
                    if self.bytecode[j] == 0x55 { return vec![SecurityFinding {
                        severity: crate::bytecode::SecuritySeverity::High,
                        description: format!("MakerDAO liquidation risk at PC {}", i),
                        pc: i, confidence: 0.82,
                    }]; }
                }
            }
        }
        Vec::new()
    }
}
