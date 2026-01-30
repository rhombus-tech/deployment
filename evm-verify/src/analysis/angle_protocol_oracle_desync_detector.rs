use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AngleProtocolVulnerability {
    OracleDesynchronization { description: String, location: usize, confidence: f32 },
    MultiOracleInconsistency { description: String, location: usize, confidence: f32 },
}

pub struct AngleProtocolOracleDesyncDetector {
    bytecode: Vec<u8>,
}

impl AngleProtocolOracleDesyncDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<AngleProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Angle Protocol uses multiple oracles for stablecoin collateral
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Multiple oracle calls without consistency check
            let oracle_call_count = section.iter().filter(|&&b| b == 0xFA).count(); // STATICCALL
            if oracle_call_count >= 2 {
                let has_consistency_check = section.windows(8).any(|w| {
                    w.contains(&0x03) && // SUB (price diff)
                    w.contains(&0x10)    // LT (threshold check)
                });
                
                if !has_consistency_check {
                    vulnerabilities.push(AngleProtocolVulnerability::OracleDesynchronization {
                        description: format!("Angle Protocol oracle desync at PC {}. Multi-oracle aggregation without deviation check. Attack: Chainlink oracle updates at T=0, custom oracle updates at T=60 → 60-second price gap → arbitrage. Require: |oracle1 - oracle2| < MAX_DEVIATION (e.g., 2%). Example: agEUR uses Chainlink + Uniswap TWAP → if desync > 2%, attacker mints at old price, redeems at new price.", i),
                        location: i,
                        confidence: 0.87,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}
