use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpermanentLossAttackVulnerability {
    NoSlippageProtection { description: String, location: usize },
    PriceManipulationVector { description: String, location: usize, confidence: f32 },
    UnbalancedPoolExploit { description: String, location: usize },
}

pub struct ImpermanentLossAttackDetector {
    bytecode: Vec<u8>,
}

impl ImpermanentLossAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ImpermanentLossAttackVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_swap_function(i) {
                if !self.has_slippage_check(i, i + 100) {
                    vulnerabilities.push(ImpermanentLossAttackVulnerability::NoSlippageProtection {
                        description: "Swap without slippage protection - IL amplification risk".to_string(),
                        location: i,
                    });
                }
                
                if self.vulnerable_to_price_manipulation(i, i + 100) {
                    vulnerabilities.push(ImpermanentLossAttackVulnerability::PriceManipulationVector {
                        description: "Price calculation vulnerable to manipulation - can amplify IL".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_swap_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // swap() selector: 0x022c0d9f
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0x02, 0x2c, 0x0d, 0x9f])
    }
    
    fn has_slippage_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Slippage check: amountOut >= minAmountOut
        self.bytecode[start..range_end].iter().any(|&b| b == 0x10 || b == 0x11) // LT/GT
    }
    
    fn vulnerable_to_price_manipulation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Uses reserves directly without TWAP
        let uses_reserves = self.bytecode[start..range_end].windows(4).any(|w| w == [0x09, 0x02, 0xf1, 0xac]); // getReserves()
        let has_twap = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x42).count() > 1; // Multiple TIMESTAMP
        uses_reserves && !has_twap
    }
}
