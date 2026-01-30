use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeLiquidityDrainDetectorVulnerability {
    UnlimitedWithdrawal { description: String, location: usize },
}

pub struct BridgeLiquidityDrainDetector { bytecode: Vec<u8> }

impl BridgeLiquidityDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BridgeLiquidityDrainDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        // Look for large transfers out
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xf1 { // CALL (transfer)
                // Check for withdrawal limits
                let has_limit = self.bytecode[i.saturating_sub(30)..i]
                    .windows(2).any(|w| w[0] == 0x10 || w[0] == 0x11); // LT or GT
                if !has_limit {
                    vulnerabilities.push(BridgeLiquidityDrainDetectorVulnerability::UnlimitedWithdrawal {
                        description: "Bridge withdrawal without limit check".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}