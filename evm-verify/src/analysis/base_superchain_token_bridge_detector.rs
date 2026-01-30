use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BaseSuperchainTokenBridgeVulnerability {
    CrossChainMessageReplay { description: String, location: usize, confidence: f32 },
    BridgeDepositManipulation { description: String, location: usize, confidence: f32 },
    WithdrawalProofForgery { description: String, location: usize, confidence: f32 },
}

pub struct BaseSuperchainTokenBridgeDetector {
    bytecode: Vec<u8>,
}

impl BaseSuperchainTokenBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BaseSuperchainTokenBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.processes_cross_chain_message() && !self.tracks_nonce() {
            vulnerabilities.push(BaseSuperchainTokenBridgeVulnerability::CrossChainMessageReplay {
                description: "Cross-chain message without nonce tracking - replay attack".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.handles_deposit() && !self.validates_chain_id() {
            vulnerabilities.push(BaseSuperchainTokenBridgeVulnerability::BridgeDepositManipulation {
                description: "Bridge deposit without chain ID validation - wrong chain deposit".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.processes_withdrawal() && !self.verifies_merkle_proof() {
            vulnerabilities.push(BaseSuperchainTokenBridgeVulnerability::WithdrawalProofForgery {
                description: "Withdrawal without merkle proof verification - forged withdrawal".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn processes_cross_chain_message(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        sload_count > 4 && call_count > 2
    }
    
    fn tracks_nonce(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sload_count > 5 && sstore_count > 4 && add_count > 2
    }
    
    fn handles_deposit(&self) -> bool {
        let callvalue_count = self.bytecode.iter().filter(|&&b| b == 0x34).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        callvalue_count > 0 && sstore_count > 3 && log_count > 1
    }
    
    fn validates_chain_id(&self) -> bool {
        let chainid_count = self.bytecode.iter().filter(|&&b| b == 0x46).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        chainid_count > 0 && eq_count > 2
    }
    
    fn processes_withdrawal(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        call_count > 1 && sub_count > 1
    }
    
    fn verifies_merkle_proof(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sha3_count > 3 && eq_count > 3 && jumpi_count > 4
    }
}
