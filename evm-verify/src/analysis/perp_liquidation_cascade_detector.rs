use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerpLiquidationCascadeVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct PerpLiquidationCascadeDetector {
    bytecode: Vec<u8>,
}

impl PerpLiquidationCascadeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PerpLiquidationCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern-based detection for perp liquidation cascade
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for suspicious patterns
            if self.bytecode[i] == 0xf1 || // CALL
               self.bytecode[i] == 0xf4 || // DELEGATECALL
               self.bytecode[i] == 0x55 {  // SSTORE
                vulnerabilities.push(PerpLiquidationCascadeVulnerability::Medium {
                    description: "Potential vulnerability pattern detected".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
}
