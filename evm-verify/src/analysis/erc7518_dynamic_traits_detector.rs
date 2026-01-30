/// ERC-7518 Dynamic Traits for NFTs Detector
/// On-chain mutable NFT traits/attributes

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7518Vulnerability {
    pub vulnerability_type: Erc7518VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7518VulnerabilityType {
    UnauthorizedTraitModification,  // Anyone can modify traits
    TraitOracleManipulation,        // Oracle data manipulated
    TraitHistoryDeletion,           // Trait change history erased
    TraitImmutabilityViolation,     // "Immutable" traits changed
    TraitValueRangeViolation,       // Invalid trait values
}

pub struct Erc7518DynamicTraitsDetector {
    bytecode: Vec<u8>,
}

impl Erc7518DynamicTraitsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7518Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Trait modification without access control
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut modifies_trait = false;
            let mut checks_auth = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0x55 { modifies_trait = true; }
                if self.bytecode[j] == 0x33 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // CALLER EQ
                    checks_auth = true;
                }
            }
            
            if modifies_trait && !checks_auth {
                vulnerabilities.push(Erc7518Vulnerability {
                    vulnerability_type: Erc7518VulnerabilityType::UnauthorizedTraitModification,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "NFT trait modified without authorization.".to_string(),
                    exploit_scenario: "1. Game NFT has dynamic 'level' trait\n\
                                      2. Level 100 NFT worth $10K\n\
                                      3. Attacker buys Level 1 NFT for $100\n\
                                      4. Calls setTrait(tokenId, 'level', 100)\n\
                                      5. No owner validation\n\
                                      6. Trait updated to Level 100\n\
                                      7. Attacker sells for $10K\n\
                                      8. Buyer gets worthless boosted NFT".to_string(),
                    recommendation: "Require NFT owner or authorized operator. Add onlyOwner modifier. \
                                  Validate trait oracle signatures.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
