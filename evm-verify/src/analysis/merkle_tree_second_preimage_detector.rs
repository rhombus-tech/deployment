use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MerkleTreeSecondPreimageVulnerability {
    NoLeafHashDifferentiation { description: String, location: usize, confidence: f32 },
    InternalNodeAsLeaf { description: String, location: usize },
    HashCollisionPossible { description: String, location: usize },
}

pub struct MerkleTreeSecondPreimageDetector {
    bytecode: Vec<u8>,
}

impl MerkleTreeSecondPreimageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MerkleTreeSecondPreimageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_merkle_proof_verification(i, i + 100) {
                if !self.differentiates_leaf_and_internal(i, i + 100) {
                    vulnerabilities.push(MerkleTreeSecondPreimageVulnerability::NoLeafHashDifferentiation {
                        description: "Merkle proof without leaf/internal node differentiation - second preimage attack".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_merkle_proof_verification(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Multiple KECCAK256 in sequence (merkle path hashing)
        let keccak_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x20)
            .count();
        
        keccak_count >= 3
    }
    
    fn differentiates_leaf_and_internal(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Should have different hash computation for leaves (e.g., prefix byte)
        // Look for conditional logic around KECCAK256
        let has_conditional = self.bytecode[start..range_end]
            .windows(10)
            .any(|w| w.contains(&0x20) && w.contains(&0x57));
        
        has_conditional
    }
}
