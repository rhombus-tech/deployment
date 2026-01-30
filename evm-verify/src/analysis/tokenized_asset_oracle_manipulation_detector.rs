use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenizedAssetOracleManipulationVulnerability {
    IlliquidAssetPricing { description: String, location: usize, confidence: f32 },
    SingleOracleRWA { description: String, location: usize, confidence: f32 },
    OffChainPriceDiscrepancy { description: String, location: usize, confidence: f32 },
}

pub struct TokenizedAssetOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl TokenizedAssetOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TokenizedAssetOracleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.prices_tokenized_assets() && !self.uses_multiple_sources() {
            vulnerabilities.push(TokenizedAssetOracleManipulationVulnerability::SingleOracleRWA {
                description: "Tokenized asset pricing with single oracle - manipulation risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.values_illiquid_assets() && !self.applies_discount() {
            vulnerabilities.push(TokenizedAssetOracleManipulationVulnerability::IlliquidAssetPricing {
                description: "Illiquid asset valuation without liquidity discount - overvaluation risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_oracle_price() && !self.validates_offchain_consistency() {
            vulnerabilities.push(TokenizedAssetOracleManipulationVulnerability::OffChainPriceDiscrepancy {
                description: "Oracle price without off-chain validation - real-world price discrepancy".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn prices_tokenized_assets(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        staticcall_count > 1 && mul_count > 3 && div_count > 2
    }
    
    fn uses_multiple_sources(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        staticcall_count > 3 && add_count > 2 && div_count > 1
    }
    
    fn values_illiquid_assets(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        staticcall_count > 1 && sstore_count > 2
    }
    
    fn applies_discount(&self) -> bool {
        // Discount factor multiplication
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        mul_count > 4 && div_count > 2 && sub_count > 1
    }
    
    fn uses_oracle_price(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 1
    }
    
    fn validates_offchain_consistency(&self) -> bool {
        // Timestamp-based staleness checks
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 1 && sub_count > 1 && lt_count > 0
    }
}
