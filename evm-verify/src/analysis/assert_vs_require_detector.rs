use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssertVsRequireVulnerability {
    UsingAssertInProduction { description: String, location: usize, confidence: f32 },
    AssertDoesNotRefundGas { description: String, location: usize },
}

pub struct AssertVsRequireDetector {
    bytecode: Vec<u8>,
}

impl AssertVsRequireDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AssertVsRequireVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // assert() uses INVALID opcode (0xFE) which consumes all gas
        // require() uses REVERT opcode (0xFD) which refunds gas
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xFE { // INVALID (assert)
                vulnerabilities.push(AssertVsRequireVulnerability::UsingAssertInProduction {
                    description: "Using assert() instead of require() - does not refund gas on failure".to_string(),
                    location: i,
                    confidence: 0.95,
                });
            }
        }
        
        vulnerabilities
    }
}
