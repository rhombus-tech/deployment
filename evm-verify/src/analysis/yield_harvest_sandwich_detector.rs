use serde::{Serialize, Deserialize};

/// Yield Harvest Sandwich Detection
/// Detects when harvest functions can be front-run for profit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YieldHarvestSandwichDetectorVulnerability {
    HarvestFrontrunRisk {
        description: String,
        location: usize,
    },
    NoSlippageProtection {
        description: String,
        location: usize,
    },
}

pub struct YieldHarvestSandwichDetector {
    bytecode: Vec<u8>,
}

impl YieldHarvestSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<YieldHarvestSandwichDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for harvest/compound functions
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                // Check if function does yield distribution (multiple SSTORE)
                let has_yield_distribution = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                    .iter()
                    .filter(|&&b| b == 0x55)
                    .count() >= 2;
                
                if has_yield_distribution {
                    // Check for sandwich protection (deadline, slippage)
                    let has_protection = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .iter()
                        .any(|&b| b == 0x42); // TIMESTAMP check
                    
                    if !has_protection {
                        vulnerabilities.push(YieldHarvestSandwichDetectorVulnerability::HarvestFrontrunRisk {
                            description: "Harvest function without MEV protection".to_string(),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }
        
        vulnerabilities
    }
}