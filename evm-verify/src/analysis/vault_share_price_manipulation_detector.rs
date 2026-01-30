use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultSharePriceManipulationVulnerability {
    DonateToInflatePrice { description: String, location: usize, confidence: f32 },
    FirstDepositorAttack { description: String, location: usize },
    NoMinimumShares { description: String, location: usize },
}

pub struct VaultSharePriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl VaultSharePriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VaultSharePriceManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.is_vault_contract() {
            if !self.has_minimum_shares_check() {
                vulnerabilities.push(VaultSharePriceManipulationVulnerability::NoMinimumShares {
                    description: "Vault without minimum shares requirement - first depositor inflation attack".to_string(),
                    location: 0,
                });
            }
            
            if self.calculates_shares_from_balance() && !self.uses_internal_accounting() {
                vulnerabilities.push(VaultSharePriceManipulationVulnerability::DonateToInflatePrice {
                    description: "Share price based on token balance - donate to inflate share price".to_string(),
                    location: 0,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn is_vault_contract(&self) -> bool {
        // deposit selector: 0xd0e30db0 or ERC4626 deposit: 0x6e553f65
        let deposit1 = [0xd0, 0xe3, 0x0d, 0xb0];
        let deposit2 = [0x6e, 0x55, 0x3f, 0x65];
        self.bytecode.windows(4).any(|w| w == deposit1 || w == deposit2)
    }
    
    fn has_minimum_shares_check(&self) -> bool {
        // Look for minimum share amount comparison
        self.bytecode.windows(3).any(|w| (w[0] == 0x10 || w[0] == 0x11) && w[2] == 0xFD)
    }
    
    fn calculates_shares_from_balance(&self) -> bool {
        // balanceOf call pattern
        let balance_of = [0x70, 0xa0, 0x82, 0x31];
        self.bytecode.windows(4).any(|w| w == balance_of)
    }
    
    fn uses_internal_accounting(&self) -> bool {
        // Check for SSTORE (internal accounting)
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sstore_count >= 3 // Multiple storage writes suggest internal accounting
    }
}
