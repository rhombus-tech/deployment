use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionBombVulnerability {
    MerkleProofExplosion { description: String, location: usize, confidence: f32 },
    RecursiveExpansion { description: String, location: usize, confidence: f32 },
    NestedDataStructure { description: String, location: usize, confidence: f32 },
}

pub struct CompressionBombDetector {
    bytecode: Vec<u8>,
}

impl CompressionBombDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<CompressionBombVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pattern 1: Merkle proof verification without depth limit
            let has_keccak = section.contains(&0x20); // SHA3
            let has_loop = section.windows(10).any(|w| w.contains(&0x56) || w.contains(&0x57));
            let no_depth_check = !section.windows(12).any(|w| {
                w.contains(&0x10) && w.contains(&0x60) // LT with depth constant
            });
            
            if has_keccak && has_loop && no_depth_check {
                vulnerabilities.push(CompressionBombVulnerability::MerkleProofExplosion {
                    description: format!("Compression bomb at PC {}. Merkle proof without depth limit. Attack: Submit proof with depth=1000 → hash 1000 times → gas exhaustion. Small input (32 bytes * 1000 = 32KB) → huge computation (1000 hashes). Analogous to ZIP bomb: small compressed → massive decompressed. Example: Merkle airdrop → attacker provides deep proof → DOS. Kolmogorov complexity: K(proof) << computation(proof). Mitigation: Limit merkle depth (e.g., max 32), or charge linear in depth.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
            
            // Pattern 2: Recursive data structure expansion
            let has_call_self = section.windows(15).any(|w| {
                w.contains(&0x30) && w.contains(&0xF1) // ADDRESS + CALL (self-call)
            });
            
            if has_call_self {
                vulnerabilities.push(CompressionBombVulnerability::RecursiveExpansion {
                    description: format!("Recursive expansion at PC {}. Self-call or recursive structure. Attack: Trigger recursive expansion → small input → massive state. Example: Contract calls itself N times → stack depth N → exponential expansion. Or: Recursive struct unpacking → 1 byte → 1GB state. Compression ratio: 2^N expansion. Mitigation: Limit recursion depth, iterative not recursive algorithms, or explicit depth counters.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
            
            // Pattern 3: Nested loops without bounds
            let loop_count = section.windows(15).filter(|w| w.contains(&0x57)).count();
            if loop_count >= 2 {
                vulnerabilities.push(CompressionBombVulnerability::NestedDataStructure {
                    description: format!("Nested expansion at PC {}. Multiple loops detected. Attack: Nested loops → O(N^k) expansion → DOS. Example: for(i) for(j) for(k) → N^3 operations from N input. Small input → massive compute. Classic compression bomb pattern. Mitigation: Limit iteration bounds, flatten loops, or charge gas per nesting level.", i),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }
}
