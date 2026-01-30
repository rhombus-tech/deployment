/// ERC-7498 NFT Redeemable Detector
/// Physical/digital goods redemption via NFT burn

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7498Vulnerability {
    pub vulnerability_type: Erc7498VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7498VulnerabilityType {
    RedemptionWithoutBurn,          // Redeem item but keep NFT
    DoubleRedemption,                // Redeem same NFT twice
    RedemptionDeadlineBypass,        // Redeem after expiration
    UnvalidatedRedemptionRequest,    // No signature/proof validation
    PhysicalFulfillmentRace,         // Race between digital and physical
    RedemptionOracleManipulation,    // Fake fulfillment confirmation
}

pub struct Erc7498NftRedeemableDetector {
    bytecode: Vec<u8>,
}

impl Erc7498NftRedeemableDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7498Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Redemption without burn
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut processes_redemption = false;
            let mut burns_nft = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { // SSTORE (redemption state)
                    processes_redemption = true;
                }
                // Burn pattern: transfer to 0x0
                if self.bytecode[j] == 0xF1 && j + 5 < self.bytecode.len() {
                    if self.bytecode[j+1] == 0x00 { // to address(0)
                        burns_nft = true;
                    }
                }
            }
            
            if processes_redemption && !burns_nft {
                vulnerabilities.push(Erc7498Vulnerability {
                    vulnerability_type: Erc7498VulnerabilityType::RedemptionWithoutBurn,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "NFT redemption processed without burning token.".to_string(),
                    exploit_scenario: "1. Event organizer mints 1000 ticket NFTs\n\
                                      2. Each NFT redeemable for 1 physical ticket\n\
                                      3. Attacker buys NFT #123\n\
                                      4. Calls redeem(123) to get physical ticket\n\
                                      5. NFT not burned, still in attacker's wallet\n\
                                      6. Attacker sells NFT #123 to victim\n\
                                      7. Victim tries to redeem, fails (already redeemed)\n\
                                      8. Victim loses $500, attacker gets ticket + resale\n\
                                      9. Organizer oversells 2000 tickets for 1000 capacity".to_string(),
                    recommendation: "Burn NFT on redemption. Use transfer to address(0) or ERC-721 _burn. \
                                  Emit RedemptionProcessed event. Check isRedeemed mapping.".to_string(),
                });
            }
        }
        
        // Pattern: No redemption deadline check
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut processes_redemption = false;
            let mut checks_timestamp = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0x55 { processes_redemption = true; }
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x10 { // LT
                        checks_timestamp = true;
                    }
                }
            }
            
            if processes_redemption && !checks_timestamp {
                vulnerabilities.push(Erc7498Vulnerability {
                    vulnerability_type: Erc7498VulnerabilityType::RedemptionDeadlineBypass,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Redemption processed without deadline validation.".to_string(),
                    exploit_scenario: "1. Limited edition sneakers: redeem by Dec 31, 2024\n\
                                      2. NFT holder forgets to redeem\n\
                                      3. Jan 15, 2025: holder tries to redeem\n\
                                      4. No deadline check, redemption succeeds\n\
                                      5. Organizer's inventory depleted\n\
                                      6. Newer NFT holders can't redeem\n\
                                      7. $10K in unfulfillable redemptions".to_string(),
                    recommendation: "Add redemption deadline. Check block.timestamp < deadline. \
                                  Emit DeadlineMissed event.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
