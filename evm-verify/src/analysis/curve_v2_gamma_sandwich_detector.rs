use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CurveV2GammaSandwichVulnerability {
    UnprotectedGammaUpdate { description: String, location: usize, confidence: f32 },
    SandwichableSwap { description: String, location: usize, confidence: f32 },
    MissingSlippageProtection { description: String, location: usize, confidence: f32 },
}

pub struct CurveV2GammaSandwichDetector {
    bytecode: Vec<u8>,
}

impl CurveV2GammaSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CurveV2GammaSandwichVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.updates_gamma() && !self.has_reentrancy_guard() {
            vulnerabilities.push(CurveV2GammaSandwichVulnerability::UnprotectedGammaUpdate {
                description: "Curve v2 gamma update without reentrancy guard - sandwich risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.implements_swap() && !self.validates_slippage() {
            vulnerabilities.push(CurveV2GammaSandwichVulnerability::SandwichableSwap {
                description: "Swap function without slippage validation - gamma sandwich attack".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_dynamic_fee() && !self.limits_fee_change() {
            vulnerabilities.push(CurveV2GammaSandwichVulnerability::MissingSlippageProtection {
                description: "Dynamic fee without change limits - extreme slippage risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn updates_gamma(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        sstore_count > 3 && mul_count > 5 && div_count > 3
    }
    
    fn has_reentrancy_guard(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 3 && iszero_count > 2 && jumpi_count > 3
    }
    
    fn implements_swap(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 2 && sstore_count > 4
    }
    
    fn validates_slippage(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        (lt_count + gt_count) > 3 && jumpi_count > 3
    }
    
    fn uses_dynamic_fee(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        mul_count > 4 && div_count > 2 && sload_count > 5
    }
    
    fn limits_fee_change(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        (lt_count + gt_count) > 4
    }
}
