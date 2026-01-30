use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NftMetadataManipulationVulnerability {
    MutableTokenUri { description: String, location: usize, confidence: f32 },
    CentralizedMetadata { description: String, location: usize },
}

pub struct NftMetadataManipulationDetector {
    bytecode: Vec<u8>,
}

impl NftMetadataManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NftMetadataManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // setTokenURI selector: 0x162094c4 (not standard but common)
        // tokenURI selector: 0xc87b56dd
        let set_token_uri = [0x16, 0x20, 0x94, 0xc4];
        let token_uri = [0xc8, 0x7b, 0x56, 0xdd];
        
        if self.bytecode.windows(4).any(|w| w == set_token_uri) {
            vulnerabilities.push(NftMetadataManipulationVulnerability::MutableTokenUri {
                description: "NFT metadata (tokenURI) can be changed after minting - rug pull risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.bytecode.windows(4).any(|w| w == token_uri) {
            if !self.uses_ipfs_or_arweave() {
                vulnerabilities.push(NftMetadataManipulationVulnerability::CentralizedMetadata {
                    description: "NFT metadata not on IPFS/Arweave - centralized server risk".to_string(),
                    location: 0,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn uses_ipfs_or_arweave(&self) -> bool {
        // This is a heuristic - true detection needs off-chain check
        // Look for IPFS hash pattern (Qm... base58) or Arweave (43 chars)
        // In bytecode, this is difficult, so we return false to be conservative
        false
    }
}
