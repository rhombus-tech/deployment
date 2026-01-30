use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureNonceMissingVulnerability {
    NoNonceInSignature { description: String, location: usize, confidence: f32 },
    NonceNotIncremented { description: String, location: usize },
    SignatureReplayPossible { description: String, location: usize },
}

pub struct SignatureNonceMissingDetector {
    bytecode: Vec<u8>,
}

impl SignatureNonceMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SignatureNonceMissingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.verifies_signature(i, i + 100) {
                if !self.uses_nonce(i, i + 100) {
                    vulnerabilities.push(SignatureNonceMissingVulnerability::NoNonceInSignature {
                        description: "Signature verification without nonce - replay attack possible".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if self.uses_nonce(i, i + 100) && !self.increments_nonce(i, i + 100) {
                    vulnerabilities.push(SignatureNonceMissingVulnerability::NonceNotIncremented {
                        description: "Nonce used but not incremented after signature verification".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn verifies_signature(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // ecrecover precompile call at address 0x01
        self.bytecode[start..range_end].windows(2).any(|w| w[0] == 0x60 && w[1] == 0x01)
    }
    
    fn uses_nonce(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_keccak = self.bytecode[start..range_end].iter().any(|&b| b == 0x20);
        has_sload && has_keccak
    }
    
    fn increments_nonce(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_add = self.bytecode[start..range_end].iter().any(|&b| b == 0x01);
        let has_sstore = self.bytecode[start..range_end].iter().any(|&b| b == 0x55);
        has_add && has_sstore
    }
}
