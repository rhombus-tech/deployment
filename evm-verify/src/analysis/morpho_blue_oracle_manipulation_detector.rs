use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MorphoBlueOracleManipulationVulnerability {
    UncheckedOraclePrice { description: String, location: usize, confidence: f32 },
    OraclePriceDeviation { description: String, location: usize, confidence: f32 },
    SingleOracleDependency { description: String, location: usize, confidence: f32 },
}

pub struct MorphoBlueOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl MorphoBlueOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MorphoBlueOracleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.fetches_oracle_price() && !self.validates_price_bounds() {
            vulnerabilities.push(MorphoBlueOracleManipulationVulnerability::UncheckedOraclePrice {
                description: "Oracle price fetch without bounds check - extreme price acceptance".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.uses_price_data() && !self.checks_deviation() {
            vulnerabilities.push(MorphoBlueOracleManipulationVulnerability::OraclePriceDeviation {
                description: "Price usage without deviation check - manipulation risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.depends_on_oracle() && !self.has_fallback_oracle() {
            vulnerabilities.push(MorphoBlueOracleManipulationVulnerability::SingleOracleDependency {
                description: "Single oracle dependency - no redundancy".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn fetches_oracle_price(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        (staticcall_count + call_count) > 2
    }
    
    fn validates_price_bounds(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        gt_count > 1 && lt_count > 1 && jumpi_count > 2
    }
    
    fn uses_price_data(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 2 && div_count > 1
    }
    
    fn checks_deviation(&self) -> bool {
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        sub_count > 2 && div_count > 1 && lt_count > 1
    }
    
    fn depends_on_oracle(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 1
    }
    
    fn has_fallback_oracle(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        staticcall_count > 3 && iszero_count > 2 && jumpi_count > 3
    }
}
