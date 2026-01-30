use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc4626InflationAttackVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct Erc4626InflationAttackDetector {
    bytecode: Vec<u8>,
}

impl Erc4626InflationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc4626InflationAttackVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // ERC4626 specific first depositor attack
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x04 && // DIV (shares calculation)
               i > 5 && self.bytecode[i-5] == 0x54 { // SLOAD (totalSupply)
                let has_min_shares_check = self.bytecode[i..i+15]
                    .windows(2)
                    .any(|w| w[0] == 0x11 && w[1] == 0x57); // GT, JUMPI
                if !has_min_shares_check {
                    vulnerabilities.push(Erc4626InflationAttackVulnerability::Critical {
                        description: "ERC4626 inflation attack: No minimum shares requirement".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
