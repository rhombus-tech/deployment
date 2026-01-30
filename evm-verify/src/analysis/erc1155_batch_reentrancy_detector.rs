use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC1155BatchReentrancyVulnerability {
    BatchTransferReentrancy { description: String, location: usize, confidence: f32 },
    OnBatchReceivedHookExploit { description: String, location: usize, confidence: f32 },
}

pub struct ERC1155BatchReentrancyDetector {
    bytecode: Vec<u8>,
}

impl ERC1155BatchReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ERC1155BatchReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // ERC-1155 safeBatchTransferFrom has unique reentrancy risks vs single transfer
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // safeBatchTransferFrom selector: 0x2eb2c2d6
            let has_batch_transfer = section.windows(4).any(|w| {
                w == &[0x2e, 0xb2, 0xc2, 0xd6]
            });
            
            if has_batch_transfer {
                // Check for state changes before callback
                let has_state_before_callback = section.windows(20).any(|w| {
                    let has_sstore = w.contains(&0x55); // SSTORE
                    let has_call = w.iter().position(|&b| b == 0xF1).is_some(); // CALL
                    has_sstore && has_call && w.iter().position(|&b| b == 0x55).unwrap() < w.iter().position(|&b| b == 0xF1).unwrap()
                });
                
                if has_state_before_callback {
                    vulnerabilities.push(ERC1155BatchReentrancyVulnerability::BatchTransferReentrancy {
                        description: format!("ERC-1155 batch transfer reentrancy at PC {}. safeBatchTransferFrom calls onERC1155BatchReceived hook. Risk: State updated before hook → hook re-enters → inconsistent state. Attack: 1) Transfer [id1, id2, id3] batch, 2) Hook called with all IDs, 3) Hook re-enters transferring same IDs, 4) Double-spend. Different from single transfer: batch processes multiple IDs → larger attack surface. Use ReentrancyGuard or checks-effects-interactions.", i),
                        location: i,
                        confidence: 0.88,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}
