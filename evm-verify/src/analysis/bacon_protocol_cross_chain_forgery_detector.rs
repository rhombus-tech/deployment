use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BaconProtocolVulnerability {
    CrossChainMessageForgery { description: String, location: usize, confidence: f32 },
    InsufficientMessageValidation { description: String, location: usize, confidence: f32 },
}

pub struct BaconProtocolCrossChainForgeryDetector {
    bytecode: Vec<u8>,
}

impl BaconProtocolCrossChainForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BaconProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Cross-chain message handling without proper validation
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: Process cross-chain message without nonce/sequence validation
            let has_message_processing = section.contains(&0x35) && section.contains(&0xF1); // CALLDATALOAD + CALL
            
            let has_nonce_check = section.windows(8).any(|w| {
                w.contains(&0x54) && // SLOAD (nonce)
                w.contains(&0x01) && // ADD (increment)
                w.contains(&0x14)    // EQ (verify)
            });
            
            if has_message_processing && !has_nonce_check {
                vulnerabilities.push(BaconProtocolVulnerability::CrossChainMessageForgery {
                    description: format!("Cross-chain message forgery at PC {}. Bacon Protocol/cross-chain bridges: messages lack replay protection. Attack: Capture valid message from chain A, replay on chain B. Example: Bridge processes mint(user, 1000) on Ethereum → attacker replays same message on Arbitrum → double-mint. Required: sequential nonce OR consumed message hash tracking.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
        }
        
        vulnerabilities
    }
}
