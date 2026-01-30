use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FraxFrxethDualOracleVulnerability {
    OracleDesynchronization { description: String, location: usize, confidence: f32 },
    SingleOracleFailure { description: String, location: usize, confidence: f32 },
    PriceDiscrepancyExploit { description: String, location: usize, confidence: f32 },
}

pub struct FraxFrxethDualOracleDetector {
    bytecode: Vec<u8>,
}

impl FraxFrxethDualOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FraxFrxethDualOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.queries_multiple_oracles() && !self.compares_prices() {
            vulnerabilities.push(FraxFrxethDualOracleVulnerability::OracleDesynchronization {
                description: "Multiple oracle queries without comparison - desync exploit".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.relies_on_oracle() && !self.has_fallback() {
            vulnerabilities.push(FraxFrxethDualOracleVulnerability::SingleOracleFailure {
                description: "Single oracle dependency without fallback - oracle failure DoS".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_price_data() && !self.validates_deviation() {
            vulnerabilities.push(FraxFrxethDualOracleVulnerability::PriceDiscrepancyExploit {
                description: "Price usage without deviation check - large discrepancy exploit".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn queries_multiple_oracles(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 2
    }
    
    fn compares_prices(&self) -> bool {
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sub_count > 1 && (lt_count + gt_count) > 2
    }
    
    fn relies_on_oracle(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        staticcall_count > 1 && iszero_count > 1
    }
    
    fn has_fallback(&self) -> bool {
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        jumpi_count > 4 && staticcall_count > 2
    }
    
    fn uses_price_data(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 2 && div_count > 1
    }
    
    fn validates_deviation(&self) -> bool {
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sub_count > 1 && div_count > 1 && lt_count > 1 && jumpi_count > 3
    }
}
