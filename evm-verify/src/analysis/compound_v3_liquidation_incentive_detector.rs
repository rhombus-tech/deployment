use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompoundV3LiquidationIncentiveVulnerability {
    ExcessiveLiquidationBonus { description: String, location: usize, confidence: f32 },
    LiquidationThresholdManipulation { description: String, location: usize, confidence: f32 },
    IncentiveArbitrage { description: String, location: usize, confidence: f32 },
}

pub struct CompoundV3LiquidationIncentiveDetector {
    bytecode: Vec<u8>,
}

impl CompoundV3LiquidationIncentiveDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompoundV3LiquidationIncentiveVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.calculates_liquidation_bonus() && !self.caps_bonus() {
            vulnerabilities.push(CompoundV3LiquidationIncentiveVulnerability::ExcessiveLiquidationBonus {
                description: "Liquidation bonus without cap - excessive bonus extraction".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.checks_liquidation_threshold() && !self.validates_price_freshness() {
            vulnerabilities.push(CompoundV3LiquidationIncentiveVulnerability::LiquidationThresholdManipulation {
                description: "Threshold check without price freshness - stale price manipulation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.provides_incentive() && !self.prevents_flash_loan_arbitrage() {
            vulnerabilities.push(CompoundV3LiquidationIncentiveVulnerability::IncentiveArbitrage {
                description: "Incentive without flash loan protection - arbitrage exploit".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn calculates_liquidation_bonus(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        mul_count > 3 && div_count > 2 && sub_count > 1
    }
    
    fn caps_bonus(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 4 && lt_count > 1 && jumpi_count > 2
    }
    
    fn checks_liquidation_threshold(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        sload_count > 5 && mul_count > 2 && lt_count > 1
    }
    
    fn validates_price_freshness(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 0 && sub_count > 1 && lt_count > 1
    }
    
    fn provides_incentive(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        mul_count > 2 && call_count > 1
    }
    
    fn prevents_flash_loan_arbitrage(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let number_count = self.bytecode.iter().filter(|&&b| b == 0x43).count();
        sload_count > 5 && eq_count > 3 && number_count > 0
    }
}
