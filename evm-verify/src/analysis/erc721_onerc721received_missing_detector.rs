use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc721Onerc721receivedMissingVulnerability {
    SafeTransferToContract { description: String, location: usize, confidence: f32 },
    NoReceiverCheck { description: String, location: usize },
}

pub struct Erc721Onerc721receivedMissingDetector {
    bytecode: Vec<u8>,
}

impl Erc721Onerc721receivedMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc721Onerc721receivedMissingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // safeTransferFrom selector: 0x42842e0e
        let safe_transfer = [0x42, 0x84, 0x2e, 0x0e];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == safe_transfer) {
                if !self.calls_onerc721received(i, i + 100) {
                    vulnerabilities.push(Erc721Onerc721receivedMissingVulnerability::NoReceiverCheck {
                        description: "safeTransferFrom doesn't call onERC721Received - NFT can be locked".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn calls_onerc721received(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // onERC721Received selector: 0x150b7a02
        let on_received = [0x15, 0x0b, 0x7a, 0x02];
        self.bytecode[start..range_end].windows(4).any(|w| w == on_received)
    }
}
