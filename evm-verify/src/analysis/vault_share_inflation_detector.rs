use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultShareInflationVulnerability {
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

pub struct VaultShareInflationDetector {
    bytecode: Vec<u8>,
}

impl VaultShareInflationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VaultShareInflationVulnerability> {
        
        // Check for ERC4626 vault patterns with donation attack vectors
        let mut vulnerabilities = Vec::new();
        
        // Look for first deposit vulnerability patterns
        // Pattern: totalAssets / totalSupply without proper initialization check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for CALLDATALOAD, SLOAD, DIV sequence (share calculation)
            if self.bytecode[i] == 0x35 && // CALLDATALOAD
               i + 10 < self.bytecode.len() &&
               self.bytecode[i+5] == 0x54 && // SLOAD (totalSupply)
               self.bytecode[i+10] == 0x04 { // DIV
                
                // Check if there's a zero-check before division
                let has_zero_check = self.bytecode[i.saturating_sub(5)..i]
                    .windows(2)
                    .any(|w| w[0] == 0x15 || w[0] == 0x14); // ISZERO or EQ
                
                if !has_zero_check {
                    vulnerabilities.push(VaultShareInflationVulnerability::Critical {
                        description: "First depositor attack: Share calculation without zero-supply check".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    
    }
}
