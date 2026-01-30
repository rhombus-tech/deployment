use crate::bytecode::SecurityFinding;
pub struct AllbridgeLiquidityDetector { bytecode: Vec<u8> }
impl AllbridgeLiquidityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 && self.bytecode[i+1] == 0x57 {
                let mut has_liquidity_check = false;
                for j in (i + 5)..((i + 20).min(self.bytecode.len())) {
                    if self.bytecode[j] == 0x10 && j + 3 < self.bytecode.len() && matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                        has_liquidity_check = true; break;
                    }
                }
                if !has_liquidity_check { return vec![SecurityFinding {
                    severity: crate::bytecode::SecuritySeverity::Medium,
                    description: format!("Allbridge liquidity bypass at PC {}", i),
                    pc: i, confidence: 0.78
                }]; }
            }
        }
        Vec::new()
    }
}
