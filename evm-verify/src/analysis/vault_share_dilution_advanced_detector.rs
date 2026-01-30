use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultShareDilutionAdvancedDetectorVulnerability {
    FirstDepositDilution { description: String, location: usize },
    MissingMinimumShares { description: String, location: usize },
}

pub struct VaultShareDilutionAdvancedDetector { bytecode: Vec<u8> }

impl VaultShareDilutionAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<VaultShareDilutionAdvancedDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x04 { // DIV (share calculation)
                let has_min_check = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(2).any(|w| w[0] == 0x10 || w[0] == 0x11);
                if !has_min_check {
                    vulnerabilities.push(VaultShareDilutionAdvancedDetectorVulnerability::MissingMinimumShares {
                        description: "Share calculation without minimum check".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}