use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UniswapV4PoolIdVulnerability {
    PoolIdHashCollision { description: String, location: usize, confidence: f32 },
    WeakPoolIdGeneration { description: String, location: usize, confidence: f32 },
}

pub struct UniswapV4PoolIdCollisionDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4PoolIdCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<UniswapV4PoolIdVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_pool_id_generation());
        vulnerabilities
    }
    
    fn detect_pool_id_generation(&self) -> Vec<UniswapV4PoolIdVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Uniswap V4 uses singleton pattern: poolId = keccak256(abi.encode(token0, token1, fee, tickSpacing, hooks))
        // Pattern: SHA3/KECCAK256 (0x20) with multiple inputs
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x20 { // SHA3/KECCAK256
                let section = &self.bytecode[i.saturating_sub(30)..std::cmp::min(i + 20, self.bytecode.len())];
                
                // Check if multiple values being hashed (pool ID pattern)
                let has_multiple_inputs = section.windows(10).filter(|w| {
                    w.contains(&0x52) || w.contains(&0x53) // MSTORE or MSTORE8
                }).count() >= 4;
                
                if has_multiple_inputs {
                    // Check for collision prevention (e.g., nonce, unique salt)
                    let has_collision_prevention = section.contains(&0x42) || // TIMESTAMP
                                                  section.contains(&0x33) || // NUMBER (block)
                                                  section.contains(&0x5B);   // JUMPDEST (nonce pattern)
                    
                    if !has_collision_prevention {
                        vulnerabilities.push(UniswapV4PoolIdVulnerability::WeakPoolIdGeneration {
                            description: format!("Pool ID generation at PC {} without collision prevention. Uniswap V4 singleton: poolId = hash(token0, token1, fee, tickSpacing, hooks). Risk: If hook address predictable or fee/tickSpacing limited values, birthday paradox → ID collisions. With 2^64 pools, collision probability ~40% at 2^32 pools. Add nonce or timestamp to hash inputs.", i),
                            location: i,
                            confidence: 0.86,
                        });
                    }
                    
                    // Check if hook address included in hash
                    let hook_in_hash = section.windows(15).any(|w| {
                        w.contains(&0x35) && // CALLDATALOAD
                        w.contains(&0x52) && // MSTORE
                        w.contains(&0x20)    // SHA3
                    });
                    
                    if hook_in_hash {
                        vulnerabilities.push(UniswapV4PoolIdVulnerability::PoolIdHashCollision {
                            description: format!("Pool ID at PC {} includes hook address in hash. V4 innovation: hooks customize pool behavior. Risk: Malicious actor brute-forces hook addresses to create collision with popular pool ID → steals liquidity/swaps. Mitigation: Include pool creator address or deployment nonce in poolId calculation.", i),
                            location: i,
                            confidence: 0.89,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
}
