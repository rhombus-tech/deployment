use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiChainNonceDesyncVulnerability {
    CrossChainReplayRisk { description: String, location: usize, confidence: f32 },
    MissingChainIdValidation { description: String, location: usize },
    NonceCollisionRisk { description: String, location: usize },
}

pub struct MultiChainNonceDesyncDetector {
    bytecode: Vec<u8>,
}

impl MultiChainNonceDesyncDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiChainNonceDesyncVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect contracts using nonces without chain ID
        if self.uses_nonce() && !self.validates_chain_id() {
            vulnerabilities.push(MultiChainNonceDesyncVulnerability::CrossChainReplayRisk {
                description: "Nonce-based logic without chain ID validation - cross-chain replay attack risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        // Detect signature verification without chain ID
        if self.verifies_signatures() && !self.includes_chain_id() {
            vulnerabilities.push(MultiChainNonceDesyncVulnerability::MissingChainIdValidation {
                description: "Signature verification missing chain ID - same account different chains replay".to_string(),
                location: 0,
            });
        }
        
        // Detect nonce increment without proper tracking
        if self.increments_nonce() && !self.has_nonce_tracking() {
            vulnerabilities.push(MultiChainNonceDesyncVulnerability::NonceCollisionRisk {
                description: "Nonce incremented without proper tracking - collision risk across chains".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn uses_nonce(&self) -> bool {
        // Look for nonce-like storage reads and comparisons
        let has_sload = self.bytecode.iter().any(|&b| b == 0x54);
        let has_eq = self.bytecode.iter().any(|&b| b == 0x14);
        has_sload && has_eq
    }
    
    fn validates_chain_id(&self) -> bool {
        // CHAINID opcode (0x46)
        self.bytecode.iter().any(|&b| b == 0x46)
    }
    
    fn verifies_signatures(&self) -> bool {
        // ECRECOVER pattern or similar
        let has_call = self.bytecode.iter().any(|&b| b == 0xF1 || b == 0xFA);
        let has_hash = self.bytecode.iter().any(|&b| b == 0x20); // SHA3
        has_call && has_hash
    }
    
    fn includes_chain_id(&self) -> bool {
        // CHAINID opcode used in signature domain
        let chainid_count = self.bytecode.iter().filter(|&&b| b == 0x46).count();
        chainid_count > 0
    }
    
    fn increments_nonce(&self) -> bool {
        // ADD followed by SSTORE (nonce increment pattern)
        self.bytecode.windows(10).any(|w| {
            w.iter().any(|&b| b == 0x01) && // ADD
            w.iter().any(|&b| b == 0x55)    // SSTORE
        })
    }
    
    fn has_nonce_tracking(&self) -> bool {
        // Multiple SLOAD/SSTORE pairs indicating proper state tracking
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sload_count >= 2 && sstore_count >= 2
    }
}
