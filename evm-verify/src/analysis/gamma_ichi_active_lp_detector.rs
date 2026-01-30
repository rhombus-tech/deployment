use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActiveLPVulnerability {
    RebalanceManipulation { description: String, location: usize, confidence: f32 },
    LiquidityRangeGriefing { description: String, location: usize, confidence: f32 },
}

pub struct GammaICHIActiveLPDetector {
    bytecode: Vec<u8>,
}

impl GammaICHIActiveLPDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ActiveLPVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Gamma/ICHI/Bunni: Automated Uniswap V3 LP management
        // Rebalances liquidity range automatically
        
        for i in 0..self.bytecode.len().saturating_sub(110) {
            let section = &self.bytecode[i..std::cmp::min(i + 110, self.bytecode.len())];
            
            // Pattern: Rebalance without slippage protection
            let has_rebalance = section.windows(15).any(|w| {
                w.contains(&0xF1) && // CALL (burn old position)
                w.contains(&0xF1) && // CALL (mint new position)
                w.contains(&0x02)    // MUL (calculate amounts)
            });
            
            let no_slippage = !section.windows(12).any(|w| {
                w.contains(&0x10) && // LT (vs expected)
                w.contains(&0x57)    // JUMPI (revert if slippage)
            });
            
            if has_rebalance && no_slippage {
                vulnerabilities.push(ActiveLPVulnerability::RebalanceManipulation {
                    description: format!("Active LP rebalance manipulation at PC {}. Gamma/ICHI rebalance: 1) Remove liquidity from old range, 2) Swap to rebalance ratio, 3) Add to new range. Attack: 1) Monitor rebalance trigger conditions, 2) Manipulate pool price right before rebalance, 3) Rebalance executes at bad price → LP loses funds, 4) Arb back. Example: Trigger rebalance at price $2000, manipulate to $2100, vault rebalances with 5% loss. Mitigation: Multi-block TWAP for rebalance price, slippage tolerance (1%), MEV protection (private tx).", i),
                    location: i,
                    confidence: 0.88,
                });
            }
            
            // Pattern: Liquidity range without min/max bounds
            let has_range_update = section.windows(10).any(|w| {
                w.contains(&0x55) && // SSTORE (tickLower)
                w.contains(&0x55)    // SSTORE (tickUpper)
            });
            
            let no_bounds = !section.windows(12).any(|w| {
                w.contains(&0x03) && // SUB (range width)
                w.contains(&0x10)    // LT (vs max)
            });
            
            if has_range_update && no_bounds {
                vulnerabilities.push(ActiveLPVulnerability::LiquidityRangeGriefing {
                    description: format!("Liquidity range griefing at PC {}. Active LP vaults set tight ranges for capital efficiency. Risk: Range too tight → all liquidity out of range after small price move → 0 fees → IL. Attack by malicious keeper: 1) Set 0.01% range around current price, 2) Price moves 0.02% → all liquidity inactive, 3) Vault earns nothing while market volatile. Or: Set massive range → spread liquidity thin → minimal fees. Mitigation: Min range width (0.5%), max range width (10%), range must include recent TWAP price.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
