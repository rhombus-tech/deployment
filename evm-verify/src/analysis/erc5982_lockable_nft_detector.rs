/// ERC-5982 Lockable/Rental NFT Detector

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5982Vulnerability {
    pub vulnerability_type: Erc5982VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc5982VulnerabilityType {
    LockBypass,                     // Lock mechanism bypassed
    UnlockBeforeExpiry,             // Unlock before rental period ends
    TransferWhileLocked,            // Transfer locked NFT
    RentalPaymentEscape,            // Renter doesn't pay
}

pub struct Erc5982LockableNftDetector {
    bytecode: Vec<u8>,
}

impl Erc5982LockableNftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc5982Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut transfers = false;
            let mut checks_lock = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { transfers = true; }
                if self.bytecode[j] == 0x54 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 {
                    checks_lock = true;
                }
            }
            
            if transfers && !checks_lock {
                vulnerabilities.push(Erc5982Vulnerability {
                    vulnerability_type: Erc5982VulnerabilityType::TransferWhileLocked,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "NFT transfer doesn't check lock status.".to_string(),
                    exploit_scenario: "1. User rents NFT for 30 days\n\
                                      2. Owner transfers NFT to another address\n\
                                      3. Renter loses access mid-rental\n\
                                      4. $10K rental payment lost".to_string(),
                    recommendation: "Check lock status before transfer. Prevent transfer while locked.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
