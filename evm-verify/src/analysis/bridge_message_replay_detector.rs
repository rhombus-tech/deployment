use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeMessageReplayVulnerability {
    NoMessageNonce { description: String, location: usize, confidence: f32 },
    NoncableReplayable { description: String, location: usize },
    NoChainIdInMessage { description: String, location: usize },
}

pub struct BridgeMessageReplayDetector {
    bytecode: Vec<u8>,
}

impl BridgeMessageReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BridgeMessageReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.processes_cross_chain_message(i, i + 100) {
                if !self.validates_nonce(i, i + 100) {
                    vulnerabilities.push(BridgeMessageReplayVulnerability::NoMessageNonce {
                        description: "Cross-chain message without nonce - replay attack across chains".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if !self.validates_chain_id(i, i + 100) {
                    vulnerabilities.push(BridgeMessageReplayVulnerability::NoChainIdInMessage {
                        description: "Bridge message without chainID validation - cross-chain replay".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn processes_cross_chain_message(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Look for external call (bridge relay)
        self.bytecode[start..range_end].iter().any(|&b| b == 0xF1 || b == 0xFA)
    }
    
    fn validates_nonce(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Nonce: SLOAD → increment → SSTORE
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_add = self.bytecode[start..range_end].iter().any(|&b| b == 0x01);
        let has_sstore = self.bytecode[start..range_end].iter().any(|&b| b == 0x55);
        has_sload && has_add && has_sstore
    }
    
    fn validates_chain_id(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x46) // CHAINID
    }
}
