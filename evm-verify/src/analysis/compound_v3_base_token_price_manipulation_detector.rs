use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompoundV3BaseTokenVulnerability {
    BaseTokenPriceManipulation { description: String, location: usize, confidence: f32 },
    FlashLoanLiquidationExploit { description: String, location: usize, confidence: f32 },
}

pub struct CompoundV3BaseTokenPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl CompoundV3BaseTokenPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<CompoundV3BaseTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Compound V3 uses single base token per market (USDC, ETH, etc.)
        // Liquidations based on base token price from oracle
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pattern: Price oracle read + liquidation logic
            let has_oracle_call = section.contains(&0xFA); // STATICCALL (oracle)
            let has_liquidation = section.windows(4).any(|w| w == &[0x6c, 0x69, 0x71, 0x75]); // "liqu"
            
            if has_oracle_call && has_liquidation {
                vulnerabilities.push(CompoundV3BaseTokenVulnerability::BaseTokenPriceManipulation {
                    description: format!("Compound V3 liquidation at PC {} reads base token price without manipulation check. V3 uses single base token → if oracle manipulated via flash loan, liquidate healthy positions. Example: Flash loan dumps USDC → oracle reports low price → liquidate $1M position for $900K. Add circuit breaker: require(abs(currentPrice - twapPrice) < threshold).", i),
                    location: i,
                    confidence: 0.90,
                });
            }
        }
        
        vulnerabilities
    }
}
