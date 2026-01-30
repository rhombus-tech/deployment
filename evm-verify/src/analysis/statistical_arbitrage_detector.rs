use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StatisticalArbitrageVulnerability {
    MultiBlockPattern { description: String, location: usize, confidence: f32 },
    MeanReversionExploit { description: String, location: usize, confidence: f32 },
}

pub struct StatisticalArbitrageDetector {
    bytecode: Vec<u8>,
}

impl StatisticalArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<StatisticalArbitrageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: Price/value comparison without considering historical volatility
            let has_price_read = section.windows(10).any(|w| {
                w.contains(&0xFA) && w.contains(&0x3E) // STATICCALL + RETURNDATACOPY
            });
            
            let has_comparison = section.contains(&0x10) || section.contains(&0x11); // LT or GT
            let no_stddev_check = !section.windows(15).any(|w| {
                w.windows(3).filter(|w2| w2.contains(&0x03)).count() > 3 // Multiple SUB (variance calc)
            });
            
            if has_price_read && has_comparison && no_stddev_check {
                vulnerabilities.push(StatisticalArbitrageVulnerability::MultiBlockPattern {
                    description: format!("Multi-block statistical arbitrage at PC {}. Protocol compares prices without volatility analysis. Attack: Observe price pattern over N blocks, predict mean reversion, profit from oscillation. Example: Oracle updates every 10 blocks, attacker identifies +2% / -2% pattern → trades pattern. Requires: Historical data, pattern recognition, timing. Mitigation: Add randomness to update frequency, use volatility-adjusted thresholds, or TWAP with longer windows.", i),
                    location: i,
                    confidence: 0.76,
                });
            }
            
            // Pattern: Rebalancing logic triggered by simple thresholds
            let has_rebalance = section.windows(20).any(|w| {
                w.contains(&0x10) && w.contains(&0x57) && w.contains(&0xF1) // LT + JUMPI + CALL
            });
            
            if has_rebalance && has_price_read {
                vulnerabilities.push(StatisticalArbitrageVulnerability::MeanReversionExploit {
                    description: format!("Mean reversion exploit at PC {}. Automated rebalancing creates predictable patterns. Attack: Force price deviation → trigger rebalance → frontrun rebalance → profit. Example: Vault rebalances when asset > 60% → attacker pushes to 61% → vault sells → attacker buys cheap. Mitigation: Add randomness to thresholds, batch rebalances, or use exponential moving averages.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
