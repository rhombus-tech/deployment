use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidStakingDepegVulnerability {
    DepegCascadeLiquidation { description: String, location: usize, confidence: f32 },
    RebasingCollateralRiskInLending { description: String, location: usize, confidence: f32 },
}

pub struct LiquidStakingDepegCascadeLiquidationDetector {
    bytecode: Vec<u8>,
}

impl LiquidStakingDepegCascadeLiquidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<LiquidStakingDepegVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // stETH/rETH depeg → lending protocol liquidations → death spiral
        for i in 0..self.bytecode.len().saturating_sub(90) {
            let section = &self.bytecode[i..std::cmp::min(i + 90, self.bytecode.len())];
            
            // Pattern: Liquidation logic using LST as collateral
            let has_liquidation = section.windows(4).any(|w| {
                w[0] == 0x63 && w[1] == 0x3c && w[2] == 0xcd && w[3] == 0xfd // liquidate()
            });
            
            let has_collateral_check = section.contains(&0xFA) && section.contains(&0x04); // Price oracle + division
            
            if has_liquidation && has_collateral_check {
                // Check if depeg circuit breaker exists
                let has_depeg_protection = section.windows(15).any(|w| {
                    w.contains(&0x03) && // SUB (price deviation)
                    w.contains(&0x10) && // LT (threshold)
                    w.contains(&0x57)    // JUMPI (halt if depegged)
                });
                
                if !has_depeg_protection {
                    vulnerabilities.push(LiquidStakingDepegVulnerability::DepegCascadeLiquidation {
                        description: format!("Liquid staking depeg cascade risk at PC {}. May-June 2022: stETH depegged to 0.93 ETH. Lending protocols using stETH as collateral: 1) stETH drops 7%, 2) Positions become under-collateralized, 3) Mass liquidations, 4) More stETH sold → deeper depeg → more liquidations. $1B+ at risk. Mitigation: Depeg circuit breaker: if |stETH/ETH - 1| > 5%, halt liquidations for 24h. Or use secondary oracle (Chainlink vs Curve pool).", i),
                        location: i,
                        confidence: 0.91,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}
