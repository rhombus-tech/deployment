use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip712DomainChainidMissingVulnerability {
    NoChainIdInDomain { description: String, location: usize, confidence: f32 },
    CrossChainReplayPossible { description: String, location: usize },
}

pub struct Eip712DomainChainidMissingDetector {
    bytecode: Vec<u8>,
}

impl Eip712DomainChainidMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip712DomainChainidMissingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.computes_domain_separator(i, i + 100) {
                if !self.includes_chainid(i, i + 100) {
                    vulnerabilities.push(Eip712DomainChainidMissingVulnerability::NoChainIdInDomain {
                        description: "EIP-712 domain separator without chainID - cross-chain replay".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn computes_domain_separator(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_keccak = self.bytecode[start..range_end].iter().any(|&b| b == 0x20);
        let mstore_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x52).count();
        has_keccak && mstore_count >= 3
    }
    
    fn includes_chainid(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x46) // CHAINID opcode
    }
}
