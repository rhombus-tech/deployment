use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidationCascadeVulnerability {
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

pub struct LiquidationCascadeDetector {
    bytecode: Vec<u8>,
}

impl LiquidationCascadeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidationCascadeVulnerability> {
        
        // Detect potential for cascading liquidations
        let mut vulnerabilities = Vec::new();
        
        // Look for liquidation functions without circuit breakers
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Check for liquidate function signature patterns
            if self.bytecode[i] == 0x36 { // CALLDATASIZE
                // Look for collateral ratio calculations
                let has_ratio_calc = self.bytecode[i..i+40]
                    .windows(3)
                    .any(|w| w[0] == 0x02 && w[1] == 0x04); // MUL, DIV
                
                if has_ratio_calc {
                    // Check for price impact limits
                    let has_limit_check = self.bytecode[i..i+40]
                        .windows(2)
                        .filter(|w| w[0] == 0x10 || w[0] == 0x11) // LT or GT
                        .count() >= 2;
                    
                    if !has_limit_check {
                        vulnerabilities.push(LiquidationCascadeVulnerability::High {
                            description: "No circuit breaker for cascade prevention".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    
    }
}
