/// ERC-4906 Metadata Update Events Detector
///
/// Detects missing or incorrect MetadataUpdate event emissions.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc4906Vulnerability {
    pub vulnerability_type: Erc4906VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc4906VulnerabilityType {
    MissingMetadataUpdateEvent,     // Metadata changed without event
    IncorrectTokenIdRange,          // BatchMetadataUpdate range wrong
    MetadataManipulation,           // Fake rarity via metadata
    EventEmissionTiming,            // Event emitted at wrong time
    UnauthorizedMetadataUpdate,     // Anyone can update metadata
}

pub struct Erc4906MetadataUpdateDetector {
    bytecode: Vec<u8>,
}

impl Erc4906MetadataUpdateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc4906Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut updates_metadata = false;
            let mut emits_event = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { // SSTORE
                    updates_metadata = true;
                }
                if self.bytecode[j] == 0xA0 || self.bytecode[j] == 0xA1 { // LOG0/LOG1
                    emits_event = true;
                }
            }
            
            if updates_metadata && !emits_event {
                vulnerabilities.push(Erc4906Vulnerability {
                    vulnerability_type: Erc4906VulnerabilityType::MissingMetadataUpdateEvent,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Metadata updated without emitting MetadataUpdate event.".to_string(),
                    exploit_scenario: "1. NFT rarity determined by metadata\n\
                                      2. Owner updates metadata to make NFT appear rare\n\
                                      3. No event emitted\n\
                                      4. Marketplaces show stale metadata\n\
                                      5. Sells at inflated price\n\
                                      6. Buyer discovers fake rarity\n\
                                      7. $50K lost on fake rare NFT".to_string(),
                    recommendation: "Emit MetadataUpdate(tokenId) on metadata changes. \
                                  Follow ERC-4906 specification.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_missing_event() {
        let bytecode = vec![
            0x55, // SSTORE (no LOG)
        ];
        
        let detector = Erc4906MetadataUpdateDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
