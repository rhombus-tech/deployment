/// Arbitrum Nitro Gas Detector
use crate::bytecode::SecurityFinding;
pub struct ArbitrumNitroGasDetector { bytecode: Vec<u8> }
impl ArbitrumNitroGasDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x5a && i + 15 < self.bytecode.len() { // GAS opcode
                for j in (i+1)..(i+15) {
                    if matches!(self.bytecode[j], 0xf1 | 0xf4) {
                        return vec![SecurityFinding {
                            severity: crate::bytecode::SecuritySeverity::Medium,
                            description: format!("L2 gas estimation issue at PC {}", i),
                            pc: i, confidence: 0.82,
                        }];
                    }
                }
            }
        }
        Vec::new()
    }
}
