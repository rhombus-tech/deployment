use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DonateToPoolAttackVulnerability {
    DirectDonationAccepted { description: String, location: usize },
    BalanceBasedAccounting { description: String, location: usize, confidence: f32 },
    NoSkimProtection { description: String, location: usize },
}

pub struct DonateToPoolAttackDetector {
    bytecode: Vec<u8>,
}

impl DonateToPoolAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DonateToPoolAttackVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.uses_balance_for_reserves(i, i + 100) {
                vulnerabilities.push(DonateToPoolAttackVulnerability::BalanceBasedAccounting {
                    description: "Uses token balance instead of internal accounting - donation attack vector".to_string(),
                    location: i,
                    confidence: 0.90,
                });
            }
            
            if self.is_sync_function(i) && !self.has_access_control(i, i + 80) {
                vulnerabilities.push(DonateToPoolAttackVulnerability::DirectDonationAccepted {
                    description: "sync() function allows anyone to force price changes via donation".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn uses_balance_for_reserves(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // balanceOf(address(this)) pattern
        let has_balance_call = self.bytecode[start..range_end].windows(4).any(|w| w == [0x70, 0xa0, 0x82, 0x31]); // balanceOf
        let has_address_this = self.bytecode[start..range_end].iter().any(|&b| b == 0x30); // ADDRESS
        has_balance_call && has_address_this
    }
    
    fn is_sync_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // sync() selector: 0xfff6cae9
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0xff, 0xf6, 0xca, 0xe9])
    }
    
    fn has_access_control(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for CALLER comparison (access control)
        self.bytecode[start..range_end].iter().any(|&b| b == 0x33) // CALLER
    }
}
