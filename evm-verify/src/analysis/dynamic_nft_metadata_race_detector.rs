use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DynamicNftMetadataRaceVulnerability {
    RevealTimingManipulation { description: String, location: usize, confidence: f32 },
    MetadataRaceCondition { description: String, location: usize },
    RarityManipulation { description: String, location: usize },
}

pub struct DynamicNftMetadataRaceDetector {
    bytecode: Vec<u8>,
}

impl DynamicNftMetadataRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DynamicNftMetadataRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // tokenURI selector: 0xc87b56dd
        let token_uri_selector = [0xc8, 0x7b, 0x56, 0xdd];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == token_uri_selector) {
                // Check if metadata can be changed after reveal
                if self.has_mutable_metadata(i, i + 80) {
                    vulnerabilities.push(DynamicNftMetadataRaceVulnerability::RevealTimingManipulation {
                        description: "NFT metadata mutable after reveal - timing manipulation for rarity".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                // Check for race condition in reveal
                if self.has_reveal_race(i, i + 80) {
                    vulnerabilities.push(DynamicNftMetadataRaceVulnerability::MetadataRaceCondition {
                        description: "Metadata reveal has race condition - frontrunning risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Check for rarity manipulation
        if self.has_rarity_calculation() && !self.has_commit_reveal() {
            vulnerabilities.push(DynamicNftMetadataRaceVulnerability::RarityManipulation {
                description: "Rarity calculated without commit-reveal - manipulation possible".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_mutable_metadata(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // SSTORE in tokenURI function suggests mutable metadata
        self.bytecode[start..range_end].iter().any(|&b| b == 0x55)
    }
    
    fn has_reveal_race(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let window = &self.bytecode[start..range_end];
        // SLOAD followed immediately by SSTORE without checks
        window.windows(10).any(|w| {
            w.iter().position(|&b| b == 0x54).is_some() &&
            w.iter().position(|&b| b == 0x55).is_some() &&
            w.iter().filter(|&&b| b == 0x57).count() == 0 // No JUMPI (no checks)
        })
    }
    
    fn has_rarity_calculation(&self) -> bool {
        // MOD operation suggests rarity/random calculation
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        mod_count > 2
    }
    
    fn has_commit_reveal(&self) -> bool {
        // SHA3 + SSTORE pattern (commitment) + later reveal
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sha3_count > 1 && sstore_count > 2
    }
}
