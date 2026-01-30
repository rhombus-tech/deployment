use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KyberSwapElasticVulnerability {
    TickLiquidityRemovalExploit { description: String, location: usize, confidence: f32 },
    ConcentratedLiquidityDrainAttack { description: String, location: usize, confidence: f32 },
    TickBitmapManipulation { description: String, location: usize, confidence: f32 },
}

pub struct KyberSwapElasticTickManipulationDetector {
    bytecode: Vec<u8>,
}

impl KyberSwapElasticTickManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<KyberSwapElasticVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // KyberSwap Elastic Nov 2023 $54.7M exploit pattern
        // Attack: Manipulate tick liquidity removal to drain pools
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern 1: Tick liquidity update without safety checks
            let has_tick_update = section.windows(4).any(|w| {
                // Look for tick-related function calls
                w.contains(&0xF1) && // CALL
                w.contains(&0x54)    // SLOAD (tick state)
            });
            
            let has_liquidity_calc = section.contains(&0x02) && section.contains(&0x04); // MUL + DIV
            let no_validation = !section.windows(5).any(|w| {
                (w.contains(&0x10) || w.contains(&0x11)) && w.contains(&0x57) // LT/GT + JUMPI
            });
            
            if has_tick_update && has_liquidity_calc && no_validation {
                vulnerabilities.push(KyberSwapElasticVulnerability::TickLiquidityRemovalExploit {
                    description: format!("KyberSwap Elastic tick manipulation at PC {}. Nov 2023 $54.7M exploit: Attacker manipulated liquidity removal from specific ticks in concentrated liquidity pools. Attack: 1) Identify tick with large liquidity, 2) Create complex swap sequence removing liquidity from tick, 3) Drain pool via arbitrage. Requires validation: tick liquidity delta checks, position boundary validation.", i),
                    location: i,
                    confidence: 0.88,
                });
            }
            
            // Pattern 2: Concentrated liquidity position manipulation
            let has_position_burn = section.windows(6).any(|w| {
                w.contains(&0x03) && // SUB (burn liquidity)
                w.contains(&0x55)    // SSTORE (update state)
            });
            
            if has_position_burn && !section.contains(&0x14) { // No EQ check
                vulnerabilities.push(KyberSwapElasticVulnerability::ConcentratedLiquidityDrainAttack {
                    description: format!("Concentrated liquidity drain vulnerability at PC {}. Uniswap V3-style pools: liquidity concentrated in narrow tick ranges. Risk: Remove liquidity from one tick → entire price range becomes illiquid → manipulate price → drain reserves. Mitigation: Enforce minimum liquidity per tick, validate tick spacing, check global liquidity invariant.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
            
            // Pattern 3: Tick bitmap manipulation (advanced)
            let has_bitmap_ops = section.contains(&0x1B) && section.contains(&0x16); // SHL + AND (bitmap operations)
            if has_bitmap_ops && has_tick_update {
                vulnerabilities.push(KyberSwapElasticVulnerability::TickBitmapManipulation {
                    description: format!("Tick bitmap manipulation at PC {}. Concentrated liquidity uses bitmaps to track initialized ticks. Risk: Manipulate bitmap to mark empty ticks as initialized → skip liquidity checks → bypass pool invariants. Example: Set bit for tick T without actual liquidity → swap through T → incorrect price calculation.", i),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }
}
