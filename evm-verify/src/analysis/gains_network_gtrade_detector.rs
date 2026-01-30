use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GainsNetworkVulnerability {
    PriceImpactFormulaManipulation { description: String, location: usize, confidence: f32 },
    SpreadManipulation { description: String, location: usize, confidence: f32 },
}

pub struct GainsNetworkGTradeDetector {
    bytecode: Vec<u8>,
}

impl GainsNetworkGTradeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<GainsNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Gains Network gTrade: Uses unique price impact formula
        // Price impact = f(position_size, OI_long, OI_short, liquidity_depth)
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern: Price impact calculation without bounds
            let has_impact_calc = section.windows(15).any(|w| {
                w.contains(&0x02) && // MUL (position size)
                w.contains(&0x04) && // DIV (by liquidity)
                w.contains(&0x03)    // SUB (OI imbalance)
            });
            
            let no_max_impact = !section.windows(10).any(|w| {
                w.contains(&0x10) && // LT (vs max)
                w.contains(&0x57)    // JUMPI (cap impact)
            });
            
            if has_impact_calc && no_max_impact {
                vulnerabilities.push(GainsNetworkVulnerability::PriceImpactFormulaManipulation {
                    description: format!("Gains Network price impact manipulation at PC {}. gTrade formula: impact = position_size * OI_imbalance / available_liquidity. Attack: 1) Build large one-sided OI (all longs), 2) Open opposite position (short) → extreme price impact, 3) Profit from mispricing. Example: $10M OI long, $1M liquidity → opening $1M short creates 30%+ impact → execution price way off oracle. Mitigation: Cap max impact at 5%, dynamic spread based on volatility, circuit breaker for extreme OI imbalance.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
            
            // Pattern: Spread calculation without minimum
            let has_spread = section.windows(12).any(|w| {
                w.contains(&0x02) && // MUL (volatility factor)
                w.contains(&0x04)    // DIV (calculate spread)
            });
            
            if has_spread && !section.contains(&0x10) { // No LT (minimum check)
                vulnerabilities.push(GainsNetworkVulnerability::SpreadManipulation {
                    description: format!("gTrade spread manipulation at PC {}. Dynamic spread based on: volatility, OI ratio, oracle freshness. Risk: Spread can be manipulated to near-zero during low volatility → adversarial trades with minimal cost. Attack: Wait for low volatility period → open massive position with 0.01% spread → close when volatility returns. Mitigation: Minimum spread (0.05%), time-weighted volatility (24h TWAP), spread floor even in calm markets.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
        }
        
        vulnerabilities
    }
}
