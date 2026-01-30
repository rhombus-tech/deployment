use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BondingCurveFlashLoanVulnerability {
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

pub struct BondingCurveFlashLoanDetector {
    bytecode: Vec<u8>,
}

impl BondingCurveFlashLoanDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BondingCurveFlashLoanVulnerability> {
        
        // Detect bonding curve vulnerable to flash loan manipulation
        let mut vulnerabilities = Vec::new();
        
        // Look for price calculations based on reserve ratios
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // DIV (price calculation)
                // Check if reserves are loaded
                let loads_reserves = self.bytecode[i.saturating_sub(15)..i]
                    .windows(2)
                    .filter(|w| w[0] == 0x54) // SLOAD
                    .count() >= 2;
                
                if loads_reserves {
                    // Check for flash loan protection (reentrancy guard)
                    let has_reentrancy_guard = self.bytecode[i.saturating_sub(20)..i]
                        .windows(3)
                        .any(|w| w[0] == 0x54 && w[1] == 0x60 && w[2] == 0x57); // SLOAD, PUSH, JUMPI
                    
                    if !has_reentrancy_guard {
                        vulnerabilities.push(BondingCurveFlashLoanVulnerability::Critical {
                            description: "Bonding curve vulnerable to flash loan price manipulation".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    
    }
}
