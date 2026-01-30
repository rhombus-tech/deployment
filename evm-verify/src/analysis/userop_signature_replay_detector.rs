use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UseropSignatureReplayVulnerability {
    NoNonceValidation { description: String, location: usize, confidence: f32 },
    NoChainIdInUserOp { description: String, location: usize },
    CrossChainReplayPossible { description: String, location: usize },
}

pub struct UseropSignatureReplayDetector {
    bytecode: Vec<u8>,
}

impl UseropSignatureReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UseropSignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // validateUserOp selector (ERC-4337): 0x3a871cdd
        let validate_userop = [0x3a, 0x87, 0x1c, 0xdd];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == validate_userop) {
                if !self.validates_nonce(i, i + 100) {
                    vulnerabilities.push(UseropSignatureReplayVulnerability::NoNonceValidation {
                        description: "UserOp signature without nonce validation - replay attack".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                if !self.includes_chain_id(i, i + 100) {
                    vulnerabilities.push(UseropSignatureReplayVulnerability::NoChainIdInUserOp {
                        description: "UserOp without chainID - cross-chain signature replay".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn validates_nonce(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        has_sload && has_eq
    }
    
    fn includes_chain_id(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x46) // CHAINID
    }
}
