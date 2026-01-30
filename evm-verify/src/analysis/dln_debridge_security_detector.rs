use crate::bytecode::SecurityFinding;
pub struct DlnDebridgeSecurityDetector { bytecode: Vec<u8> }
impl DlnDebridgeSecurityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 && self.bytecode[i+1] == 0xde {
                let mut has_order_validation = false;
                for j in (i + 5)..((i + 15).min(self.bytecode.len())) {
                    if self.bytecode[j] == 0x54 && j + 2 < self.bytecode.len() && self.bytecode[j + 1] == 0x14 {
                        has_order_validation = true; break;
                    }
                }
                if !has_order_validation { return vec![SecurityFinding {
                    severity: crate::bytecode::SecuritySeverity::Medium,
                    description: format!("deBridge DLN order validation bypass at PC {}", i),
                    pc: i, confidence: 0.75
                }]; }
            }
        }
        Vec::new()
    }
}
