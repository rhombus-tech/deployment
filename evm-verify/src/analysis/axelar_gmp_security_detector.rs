use crate::bytecode::SecurityFinding;
pub struct AxelarGmpSecurityDetector { bytecode: Vec<u8> }
impl AxelarGmpSecurityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 && self.bytecode[i+1] == 0x78 {
                let mut has_gateway_check = false;
                for j in (i + 5)..((i + 20).min(self.bytecode.len())) {
                    if self.bytecode[j] == 0x33 && j + 2 < self.bytecode.len() && self.bytecode[j + 1] == 0x14 {
                        has_gateway_check = true; break;
                    }
                }
                if !has_gateway_check {
                    return vec![SecurityFinding {
                        severity: crate::bytecode::SecuritySeverity::High,
                        description: format!("Axelar GMP gateway bypass at PC {}", i),
                        pc: i, confidence: 0.80,
                    }];
                }
            }
        }
        Vec::new()
    }
}
