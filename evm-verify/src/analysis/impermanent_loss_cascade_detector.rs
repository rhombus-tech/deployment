use serde::{Serialize, Deserialize};

/// Impermanent Loss Cascade Detection
/// Cascading LP losses when large liquidity exits trigger more exits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpermanentLossCascadeDetectorVulnerability {
    /// LP withdrawal without IL protection check
    UnprotectedLPBurn {
        description: String,
        location: usize,
    },
    /// Multiple simultaneous withdrawals can cascade
    CascadeRisk {
        description: String,
        location: usize,
    },
}

pub struct ImpermanentLossCascadeDetector {
    bytecode: Vec<u8>,
}

impl ImpermanentLossCascadeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ImpermanentLossCascadeDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for LP token burning/withdrawal
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if this is an LP balance decrease
                let is_balance_decrease = self.bytecode[i.saturating_sub(10)..i]
                    .iter()
                    .any(|&b| b == 0x03); // SUB
                
                if is_balance_decrease {
                    // Check for IL protection (price ratio check)
                    let has_price_check = self.bytecode[i.saturating_sub(30)..i]
                        .windows(3)
                        .any(|w| w[0] == 0x04 && w[2] == 0x10); // DIV, LT
                    
                    if !has_price_check {
                        vulnerabilities.push(ImpermanentLossCascadeDetectorVulnerability::UnprotectedLPBurn {
                            description: "LP withdrawal without impermanent loss check".to_string(),
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