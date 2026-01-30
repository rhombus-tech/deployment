use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AmmKInvariantVulnerability {
    /// Critical security issue detected
    Critical {
        description: String,
        location: usize,
    },
    /// High severity issue
    High {
        description: String,
        location: usize,
    },
    /// Medium severity issue
    Medium {
        description: String,
        location: usize,
    },
}

pub struct AmmKInvariantDetector {
    bytecode: Vec<u8>,
}

impl AmmKInvariantDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AmmKInvariantVulnerability> {
        
        // Check for constant product AMM violations (x * y = k)
        let mut vulnerabilities = Vec::new();
        
        // Look for MUL operations without proper invariant checks
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x02 { // MUL
                // Check for reserve calculations
                let has_reserve_load = self.bytecode[i.saturating_sub(10)..i]
                    .iter()
                    .any(|&b| b == 0x54); // SLOAD
                
                if has_reserve_load {
                    // Look for REVERT after invariant check
                    let has_revert = self.bytecode[i..i+15]
                        .iter()
                        .any(|&b| b == 0xfd); // REVERT
                    
                    if !has_revert {
                        vulnerabilities.push(AmmKInvariantVulnerability::High {
                            description: "AMM invariant not enforced: Missing k-value validation".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    
    }
}
