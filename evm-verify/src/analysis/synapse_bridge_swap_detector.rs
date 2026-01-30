use crate::bytecode::SecurityFinding;
pub struct SynapseBridgeSwapDetector { bytecode: Vec<u8> }
impl SynapseBridgeSwapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 && self.bytecode[i+1] == 0x91 {
                let mut has_swap_validation = false;
                for j in (i + 5)..((i + 20).min(self.bytecode.len())) {
                    if self.bytecode[j] == 0x10 { has_swap_validation = true; break; }
                }
                if !has_swap_validation { return vec![SecurityFinding {
                    severity: crate::bytecode::SecuritySeverity::Medium,
                    description: format!("Synapse swap validation bypass at PC {}", i),
                    pc: i, confidence: 0.77
                }]; }
            }
        }
        Vec::new()
    }
}
