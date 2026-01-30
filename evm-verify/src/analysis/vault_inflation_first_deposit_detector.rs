use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultInflationFirstDepositVulnerability {
    NoMinimumShares { description: String, location: usize, confidence: f32 },
    FirstDepositorAdvantage { description: String, location: usize },
    SharePriceManipulation { description: String, location: usize },
}

pub struct VaultInflationFirstDepositDetector {
    bytecode: Vec<u8>,
}

impl VaultInflationFirstDepositDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VaultInflationFirstDepositVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_vault_deposit(i) {
                if !self.enforces_minimum_shares(i, i + 120) {
                    vulnerabilities.push(VaultInflationFirstDepositVulnerability::NoMinimumShares {
                        description: "Vault deposit without minimum shares requirement - inflation attack possible".to_string(),
                        location: i,
                        confidence: 0.95,
                    });
                }
                
                if self.calculates_shares_from_total_supply(i, i + 120) {
                    if !self.has_initial_deposit_protection(i, i + 120) {
                        vulnerabilities.push(VaultInflationFirstDepositVulnerability::FirstDepositorAdvantage {
                            description: "First depositor can manipulate share price via donation".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_vault_deposit(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // deposit() selector: 0xb6b55f25 or mint(): 0x6e553f65
        let selectors = [[0xb6, 0xb5, 0x5f, 0x25], [0x6e, 0x55, 0x3f, 0x65]];
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn enforces_minimum_shares(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for minimum shares validation
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x10 && w[2] == 0xFD // LT + REVERT
        })
    }
    
    fn calculates_shares_from_total_supply(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // shares = (amount * totalSupply) / totalAssets
        let has_mul = self.bytecode[start..range_end].iter().any(|&b| b == 0x02);
        let has_div = self.bytecode[start..range_end].iter().any(|&b| b == 0x04);
        has_mul && has_div
    }
    
    fn has_initial_deposit_protection(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for virtual shares or minimum initial deposit
        self.bytecode[start..range_end].windows(2).any(|w| w[0] == 0x60 && w[1] > 0x00)
    }
}
