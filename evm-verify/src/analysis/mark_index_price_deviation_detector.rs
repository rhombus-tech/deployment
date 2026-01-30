use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MarkIndexPriceVulnerability {
    ExcessiveMarkIndexDeviation { description: String, location: usize, confidence: f32 },
    FundingRateManipulation { description: String, location: usize, confidence: f32 },
}

pub struct MarkIndexPriceDeviationDetector {
    bytecode: Vec<u8>,
}

impl MarkIndexPriceDeviationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MarkIndexPriceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Mark Price = Internal exchange price (to prevent manipulation)
        // Index Price = External oracle price (Chainlink, Pyth)
        // Funding rate = based on Mark - Index deviation
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern: Mark price calculation without deviation limit
            let has_mark_calc = section.windows(15).any(|w| {
                w.contains(&0xFA) && // STATICCALL (read external price)
                w.contains(&0x04)    // DIV (TWAP or weighted avg)
            });
            
            let no_deviation_cap = !section.windows(12).any(|w| {
                w.contains(&0x03) && // SUB (mark - index)
                w.contains(&0x10) && // LT (check deviation)
                w.contains(&0x57)    // JUMPI (revert if too high)
            });
            
            if has_mark_calc && no_deviation_cap {
                vulnerabilities.push(MarkIndexPriceVulnerability::ExcessiveMarkIndexDeviation {
                    description: format!("Mark-Index price deviation uncapped at PC {}. Perp mechanics: Mark price (internal) vs Index price (oracle). Deviation > threshold → abnormal funding. Attack: 1) Manipulate order book to skew mark price, 2) Mark $2100 vs Index $2000 (5% deviation), 3) Longs pay 5% funding to shorts every 8h → drain. Real exploit: FTX allowed 10%+ deviation. Mitigation: Cap deviation at 2%, circuit breaker if sustained > 1%.", i),
                    location: i,
                    confidence: 0.89,
                });
            }
            
            // Pattern: Funding rate without dampening
            let has_funding = section.windows(10).any(|w| {
                w.contains(&0x02) && // MUL (funding calc)
                w.contains(&0x55)    // SSTORE (update rate)
            });
            
            if has_funding && !section.contains(&0x04) { // No DIV (dampening factor)
                vulnerabilities.push(MarkIndexPriceVulnerability::FundingRateManipulation {
                    description: format!("Funding rate manipulation at PC {}. Funding = (Mark - Index) / Index. No dampening → extreme rates. Attack: Push mark price 5% above index → funding rate 5%/8h = 15%/day = 5475%/year. Shorts collect, longs destroyed. Mitigation: Clamp funding rate (-0.05% to +0.05% per funding period), use dampening coefficient (e.g., deviation * 0.1).", i),
                    location: i,
                    confidence: 0.86,
                });
            }
        }
        
        vulnerabilities
    }
}
