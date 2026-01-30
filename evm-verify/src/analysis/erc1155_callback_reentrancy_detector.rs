use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc1155CallbackReentrancyVulnerability {
    UnsafeCallback { description: String, location: usize, confidence: f32 },
    NoReentrancyGuard { description: String, location: usize },
}

pub struct Erc1155CallbackReentrancyDetector {
    bytecode: Vec<u8>,
}

impl Erc1155CallbackReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc1155CallbackReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // onERC1155Received: 0xf23a6e61, onERC1155BatchReceived: 0xbc197c81
        let on_received = [0xf2, 0x3a, 0x6e, 0x61];
        let batch_received = [0xbc, 0x19, 0x7c, 0x81];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == on_received || w == batch_received) {
                if self.has_state_change_in_callback(i, i + 100) {
                    if !self.has_reentrancy_guard(i, i + 100) {
                        vulnerabilities.push(Erc1155CallbackReentrancyVulnerability::UnsafeCallback {
                            description: "ERC1155 callback modifies state without reentrancy guard".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_state_change_in_callback(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x55) // SSTORE
    }
    
    fn has_reentrancy_guard(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // nonReentrant modifier pattern: SLOAD + check + SSTORE
        let sload_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x55).count();
        sload_count >= 2 && sstore_count >= 2
    }
}
