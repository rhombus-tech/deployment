use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WooFiVulnerability {
    SPMMOracleManipulation { description: String, location: usize, confidence: f32 },
    PrivateMarketMakerExploit { description: String, location: usize, confidence: f32 },
}

pub struct WooFiSPMMDetector {
    bytecode: Vec<u8>,
}

impl WooFiSPMMDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<WooFiVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // WOOFi sPMM (Synthetic Proactive Market Maker)
        // Uses oracle price + spread instead of AMM curve
        
        for i in 0..self.bytecode.len().saturating_sub(95) {
            let section = &self.bytecode[i..std::cmp::min(i + 95, self.bytecode.len())];
            
            // Pattern: sPMM price calculation without oracle staleness check
            let has_spmm_calc = section.windows(12).any(|w| {
                w.contains(&0xFA) && // STATICCALL (oracle)
                w.contains(&0x02) && // MUL (price * amount)
                w.contains(&0x01)    // ADD (add spread)
            });
            
            let no_staleness = !section.windows(10).any(|w| {
                w.contains(&0x42) && // TIMESTAMP
                w.contains(&0x03) && // SUB (check freshness)
                w.contains(&0x57)    // JUMPI (revert if stale)
            });
            
            if has_spmm_calc && no_staleness {
                vulnerabilities.push(WooFiVulnerability::SPMMOracleManipulation {
                    description: format!("WOOFi sPMM oracle manipulation at PC {}. sPMM model: price = oracle_price ± spread (no AMM curve). Risk: Stale oracle → execute at wrong price. Attack: 1) Wait for oracle delay (Chainlink updates every 0.5% deviation), 2) Real price moved 1% but oracle stale, 3) Trade at old price + spread → arb. Example: ETH $2000 oracle, real $2020 → buy at $2000 + 0.1% spread. Mitigation: Max oracle age (60s), require multiple oracle sources, circuit breaker if price deviation > 2%.", i),
                    location: i,
                    confidence: 0.89,
                });
            }
            
            // Pattern: Spread parameter without bounds
            let has_spread_update = section.windows(8).any(|w| {
                w.contains(&0x35) && // CALLDATALOAD (new spread)
                w.contains(&0x55)    // SSTORE (update spread)
            });
            
            let no_spread_check = !section.windows(8).any(|w| {
                w.contains(&0x10) && w.contains(&0x57) // LT + JUMPI (bounds check)
            });
            
            if has_spread_update && no_spread_check {
                vulnerabilities.push(WooFiVulnerability::PrivateMarketMakerExploit {
                    description: format!("sPMM private market maker exploit at PC {}. WOOFi uses off-chain MM to set spreads. Risk: MM can set spreads to 0 or extreme values. Attack by malicious/compromised MM: 1) Set spread to 0 → trade at exact oracle price (no slippage), 2) Arb vs other DEXs, 3) Drain liquidity. Or: Set spread to 10% → users get terrible execution. Mitigation: Min spread 0.05%, max spread 2%, multi-sig for spread updates, time-delay for changes.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
