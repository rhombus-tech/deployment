use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityRemovalRaceVulnerability {
    NoMinimumLiquidityLock { description: String, location: usize, confidence: f32 },
    RemovableDuringTrade { description: String, location: usize },
}

pub struct LiquidityRemovalRaceDetector {
    bytecode: Vec<u8>,
}

impl LiquidityRemovalRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityRemovalRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // removeLiquidity selector: 0xbaa2abde
        let remove_liquidity = [0xba, 0xa2, 0xab, 0xde];
        
        if self.bytecode.windows(4).any(|w| w == remove_liquidity) {
            if !self.has_minimum_liquidity_lock() {
                vulnerabilities.push(LiquidityRemovalRaceVulnerability::NoMinimumLiquidityLock {
                    description: "Liquidity can be removed without lock period - race condition with trades".to_string(),
                    location: 0,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_minimum_liquidity_lock(&self) -> bool {
        // Look for TIMESTAMP checks (time-based lock)
        let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42);
        // Look for minimum liquidity storage slot
        let has_min_check = self.bytecode.windows(2).any(|w| w[0] == 0x10 && w[1] == 0xFD);
        has_timestamp || has_min_check
    }
}
