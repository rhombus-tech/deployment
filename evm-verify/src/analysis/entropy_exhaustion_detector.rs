use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntropyExhaustionVulnerability {
    PredictableRandomness { description: String, location: usize, confidence: f32 },
    NonceReuse { description: String, location: usize, confidence: f32 },
    BlockHashEntropy { description: String, location: usize, confidence: f32 },
}

pub struct EntropyExhaustionDetector {
    bytecode: Vec<u8>,
}

impl EntropyExhaustionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EntropyExhaustionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern 1: Using block hash as only randomness source
            let has_blockhash = section.contains(&0x40); // BLOCKHASH
            let has_modulo = section.contains(&0x06); // MOD (for randomness)
            let no_external_vrf = !section.windows(10).any(|w| w.contains(&0xFA)); // No STATICCALL to VRF
            
            if has_blockhash && has_modulo && no_external_vrf {
                vulnerabilities.push(EntropyExhaustionVulnerability::BlockHashEntropy {
                    description: format!("Entropy exhaustion at PC {}. Block hash used as sole randomness source. Attack: Block hashes are limited (only last 256 blocks), miners can manipulate, predictable after 256 blocks. Information theory: Only log₂(256) = 8 bits of entropy per draw. After N draws, entropy pool depleted. Example: Lottery using blockhash → miner withholds block if they don't win. Or: 257+ calls → hashes repeat. Shannon entropy H(X) decreases with each use. Mitigation: Use Chainlink VRF (verifiable randomness), commit-reveal with external entropy, or combine multiple unpredictable sources.", i),
                    location: i,
                    confidence: 0.89,
                });
            }
            
            // Pattern 2: Timestamp as randomness
            let has_timestamp = section.contains(&0x42); // TIMESTAMP
            if has_timestamp && has_modulo {
                vulnerabilities.push(EntropyExhaustionVulnerability::PredictableRandomness {
                    description: format!("Predictable entropy at PC {}. Timestamp used for randomness. Attack: Miners control timestamp (±15 seconds), predictable to miners. Entropy: ~4 bits per 15-second window. Not cryptographically random. Example: Raffle using timestamp % N → miner sets timestamp to winning value. Information leakage: Timestamp reveals ordering. Mitigation: Never use timestamp for randomness, use VRF or commit-reveal.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
            
            // Pattern 3: Nonce-based randomness without rotation
            let has_nonce = section.windows(15).any(|w| {
                w.contains(&0x54) && w.contains(&0x01) && w.contains(&0x55) // SLOAD + ADD + SSTORE (increment)
            });
            
            if has_nonce && has_modulo {
                vulnerabilities.push(EntropyExhaustionVulnerability::NonceReuse {
                    description: format!("Nonce exhaustion at PC {}. Sequential nonce for randomness. Attack: Nonce is deterministic counter, fully predictable. Zero entropy after observing pattern. Example: Random number = nonce % 100 → attacker knows next 1000 values. After 2^256 calls, nonce wraps → exact repetition. Mitigation: Don't use nonces for randomness, or salt with unpredictable data.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
