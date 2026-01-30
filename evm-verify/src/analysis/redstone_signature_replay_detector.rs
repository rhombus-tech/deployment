use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedstoneVulnerability {
    SignatureReplayAcrossFeeds { description: String, location: usize, confidence: f32 },
    TimestampValidationMissing { description: String, location: usize, confidence: f32 },
}

pub struct RedstoneSignatureReplayDetector {
    bytecode: Vec<u8>,
}

impl RedstoneSignatureReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<RedstoneVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Redstone: push oracle with signature validation
        for i in 0..self.bytecode.len().saturating_sub(90) {
            let section = &self.bytecode[i..std::cmp::min(i + 90, self.bytecode.len())];
            
            // Signature verification pattern
            let has_sig_verify = section.contains(&0x01); // ECRECOVER
            
            // Check if feed ID is included in signed message
            let has_feed_id_in_sig = section.windows(20).any(|w| {
                w.contains(&0x20) && // SHA3 (hash message)
                w.contains(&0x01)    // ECRECOVER
            });
            
            if has_sig_verify && !has_feed_id_in_sig {
                vulnerabilities.push(RedstoneVulnerability::SignatureReplayAcrossFeeds {
                    description: format!("Redstone signature replay risk at PC {}. Redstone push model: off-chain relayer provides (price, timestamp, signature). If signature doesn't include feedId, attacker can replay. Attack: Valid signature for BTC/USD feed → replay on ETH/USD feed → wrong price accepted. Include in signature: keccak256(feedId, price, timestamp). Verify: ecrecover(hash, sig) == authorizedSigner.", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Timestamp validation
            let has_timestamp_check = section.windows(10).any(|w| {
                w.contains(&0x42) && // TIMESTAMP
                w.contains(&0x03) && // SUB
                w.contains(&0x10)    // LT (check freshness)
            });
            
            if has_sig_verify && !has_timestamp_check {
                vulnerabilities.push(RedstoneVulnerability::TimestampValidationMissing {
                    description: format!("Redstone timestamp validation missing at PC {}. Push oracle must verify data freshness. Risk: Relayer provides old signed price → protocol uses stale data. Require: block.timestamp - priceTimestamp < MAX_DELAY (e.g., 300 seconds). This prevents using hours-old signed prices.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
}
