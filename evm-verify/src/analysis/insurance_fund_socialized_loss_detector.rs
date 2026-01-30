use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InsuranceFundVulnerability {
    SocializedLossManipulation { description: String, location: usize, confidence: f32 },
    InsuranceFundDrainAttack { description: String, location: usize, confidence: f32 },
    ADLQueueGaming { description: String, location: usize, confidence: f32 },
}

pub struct InsuranceFundSocializedLossDetector {
    bytecode: Vec<u8>,
}

impl InsuranceFundSocializedLossDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<InsuranceFundVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Perp DEX insurance fund mechanics: When liquidation fails → socialize loss across all traders
        // Attack: Manipulate to maximize socialized loss while profiting
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            let section = &self.bytecode[i..std::cmp::min(i + 120, self.bytecode.len())];
            
            // Pattern 1: Insurance fund balance check without minimum threshold
            let has_insurance_check = section.windows(10).any(|w| {
                w.contains(&0x54) && // SLOAD (insurance fund balance)
                w.contains(&0x04)    // DIV (calculate loss distribution)
            });
            
            let no_min_threshold = !section.windows(8).any(|w| {
                w.contains(&0x10) && w.contains(&0x57) // LT + JUMPI (minimum check)
            });
            
            if has_insurance_check && no_min_threshold {
                vulnerabilities.push(InsuranceFundVulnerability::SocializedLossManipulation {
                    description: format!("Insurance fund socialized loss at PC {}. Perp DEXs (dYdX, GMX, Gains): When liquidation fails to cover loss, deficit is socialized across all traders. Attack: 1) Build large position with max leverage, 2) Manipulate oracle to create huge loss, 3) Liquidation fails → insurance fund depleted → ALL traders lose proportional funds. Example: $10M position, 100x leverage → $100M loss → socialized to all users. Require: MIN_INSURANCE_RATIO check, circuit breaker if insurance < 10% of open interest.", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Pattern 2: Insurance fund withdrawal without cooldown
            let has_withdrawal = section.windows(6).any(|w| {
                w.contains(&0x03) && // SUB (reduce insurance balance)
                w.contains(&0xF1)    // CALL (transfer funds)
            });
            
            let no_cooldown = !section.contains(&0x42); // No TIMESTAMP check
            
            if has_withdrawal && no_cooldown {
                vulnerabilities.push(InsuranceFundVulnerability::InsuranceFundDrainAttack {
                    description: format!("Insurance fund drain vulnerability at PC {}. Risk: Insurance fund can be drained instantly during crisis. Attack scenario: 1) Market volatility → multiple liquidations, 2) Insurance fund drops to critical level, 3) Attacker creates additional bad debt via manipulation, 4) Fund depleted → protocol insolvent. Mitigation: Withdrawal cooldown (24h), max withdrawal per epoch (10% of fund), pause if fund < critical threshold.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
            
            // Pattern 3: ADL (Auto-Deleveraging) queue manipulation
            let has_adl_queue = section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (position data)
                w.contains(&0x02) && // MUL (PnL calc)
                w.contains(&0x55)    // SSTORE (queue position)
            });
            
            if has_adl_queue {
                vulnerabilities.push(InsuranceFundVulnerability::ADLQueueGaming {
                    description: format!("ADL queue gaming at PC {}. Auto-Deleveraging: When insurance fund empty, profitable positions are force-closed to cover losses (dYdX, Bybit, FTX). Attack: 1) Monitor ADL queue position, 2) Close/reduce position right before ADL trigger, 3) Reopen after ADL event → avoid loss. Or: Manipulate to trigger ADL on competitors. Mitigation: Randomized ADL selection, no position changes during ADL window, ADL preview disabled.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
        }
        
        vulnerabilities
    }
}
