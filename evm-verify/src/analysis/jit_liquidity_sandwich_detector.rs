use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JitLiquiditySandwichVulnerability {
    NoMinLiquidityDuration { description: String, location: usize },
    InstantAddRemove { description: String, location: usize, confidence: f32 },
    NoFeePenalty { description: String, location: usize },
}

pub struct JitLiquiditySandwichDetector {
    bytecode: Vec<u8>,
}

impl JitLiquiditySandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<JitLiquiditySandwichVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_liquidity_functions() {
            if !self.enforces_minimum_lock_period() {
                vulnerabilities.push(JitLiquiditySandwichVulnerability::NoMinLiquidityDuration {
                    description: "Liquidity can be added and removed in same block - JIT sandwich attack".to_string(),
                    location: 0,
                });
            }
            
            for i in 0..self.bytecode.len().saturating_sub(80) {
                if self.is_remove_liquidity(i) && !self.has_time_check(i, i + 80) {
                    vulnerabilities.push(JitLiquiditySandwichVulnerability::InstantAddRemove {
                        description: "Liquidity removal without time lock allows same-block JIT attacks".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_liquidity_functions(&self) -> bool {
        // addLiquidity: 0xe8e33700, removeLiquidity: 0xbaa2abde
        let selectors = [[0xe8, 0xe3, 0x37, 0x00], [0xba, 0xa2, 0xab, 0xde]];
        selectors.iter().any(|sel| {
            self.bytecode.windows(4).any(|w| w == sel)
        })
    }
    
    fn enforces_minimum_lock_period(&self) -> bool {
        // Check for timestamp-based lock
        self.bytecode.iter().any(|&b| b == 0x42) // TIMESTAMP
    }
    
    fn is_remove_liquidity(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0xba, 0xa2, 0xab, 0xde])
    }
    
    fn has_time_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x42) // TIMESTAMP
    }
}
