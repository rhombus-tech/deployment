use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossChainKeeperBypassVulnerability {
    KeeperRoleNotVerifiedCrossChain { description: String, location: usize, confidence: f32 },
    ChainIdNotCheckedInKeeper { description: String, location: usize },
    KeeperSignatureReplay { description: String, location: usize },
    MissingKeeperNonce { description: String, location: usize },
}

pub struct CrossChainKeeperBypassDetector {
    bytecode: Vec<u8>,
}

impl CrossChainKeeperBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossChainKeeperBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_cross_chain_function(i) {
                if self.has_keeper_check(i, i + 100) {
                    // Check if chainID is validated
                    if !self.validates_chain_id(i, i + 100) {
                        vulnerabilities.push(CrossChainKeeperBypassVulnerability::ChainIdNotCheckedInKeeper {
                            description: "Cross-chain keeper function doesn't validate chainID - Poly Network style exploit".to_string(),
                            location: i,
                        });
                    }
                    
                    // Check for nonce/replay protection
                    if !self.has_nonce_check(i, i + 100) {
                        vulnerabilities.push(CrossChainKeeperBypassVulnerability::MissingKeeperNonce {
                            description: "Keeper authorization without nonce - signature replay possible".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_cross_chain_function(&self, location: usize) -> bool {
        // Look for cross-chain indicators: message passing, bridge calls
        let range_end = (location + 80).min(self.bytecode.len());
        
        // External calls (cross-chain messages)
        self.bytecode[location..range_end].iter().any(|&b| b == 0xF1 || b == 0xFA)
    }
    
    fn has_keeper_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Keeper check pattern: CALLER → SLOAD → EQ → JUMPI/REVERT
        let has_caller = self.bytecode[start..range_end].iter().any(|&b| b == 0x33);
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        
        has_caller && has_sload && has_eq
    }
    
    fn validates_chain_id(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // CHAINID opcode: 0x46
        self.bytecode[start..range_end].iter().any(|&b| b == 0x46)
    }
    
    fn has_nonce_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Nonce pattern: SLOAD → ADD → SSTORE (increment)
        let sload_positions: Vec<_> = self.bytecode[start..range_end]
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x54)
            .map(|(i, _)| i)
            .collect();
        
        for pos in sload_positions {
            let check_end = (pos + 10).min(range_end - start);
            if self.bytecode[start + pos..start + check_end].contains(&0x01) && // ADD
               self.bytecode[start + pos..start + check_end].contains(&0x55) { // SSTORE
                return true;
            }
        }
        
        false
    }
}
