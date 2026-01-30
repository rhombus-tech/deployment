use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AaveLiquidationManipulationVulnerability {
    HealthFactorManipulable { description: String, location: usize, confidence: f32 },
    LiquidationBonusTooHigh { description: String, location: usize, bonus_bps: u64 },
    NoLiquidationThreshold { description: String, location: usize },
    FlashLoanLiquidationExploit { description: String, location: usize },
}

pub struct AaveLiquidationManipulationDetector {
    bytecode: Vec<u8>,
}

impl AaveLiquidationManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AaveLiquidationManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_liquidation_call(i) {
                if !self.validates_health_factor_properly(i, i + 120) {
                    vulnerabilities.push(AaveLiquidationManipulationVulnerability::HealthFactorManipulable {
                        description: "Liquidation without proper health factor validation - manipulable via price oracle".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
                
                if let Some(bonus) = self.get_liquidation_bonus(i, i + 120) {
                    // >15% liquidation bonus is dangerous
                    if bonus > 1500 {
                        vulnerabilities.push(AaveLiquidationManipulationVulnerability::LiquidationBonusTooHigh {
                            description: format!("Liquidation bonus of {}bps too high - profitable to manipulate", bonus),
                            location: i,
                            bonus_bps: bonus,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_liquidation_call(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // liquidationCall selector: 0x00a718a9
        self.bytecode[location..location + 20]
            .windows(4)
            .any(|w| w == [0x00, 0xa7, 0x18, 0xa9])
    }
    
    fn validates_health_factor_properly(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Health factor validation: collateral * liquidationThreshold / debt
        // Pattern: MUL + DIV + comparison with 1e18
        let mut has_mul = false;
        let mut has_div = false;
        let mut has_comparison = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x02 { has_mul = true; }
            if has_mul && self.bytecode[i] == 0x04 { has_div = true; }
            if has_div && (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) {
                has_comparison = true;
            }
        }
        
        has_mul && has_div && has_comparison
    }
    
    fn get_liquidation_bonus(&self, start: usize, end: usize) -> Option<u64> {
        let range_end = end.min(self.bytecode.len());
        
        // Liquidation bonus in basis points (10000 = 100%)
        for i in start..range_end.saturating_sub(3) {
            if self.bytecode[i] == 0x61 { // PUSH2
                if i + 2 < range_end {
                    let value = ((self.bytecode[i + 1] as u64) << 8) | (self.bytecode[i + 2] as u64);
                    // Liquidation bonus typically 500-2000 bps
                    if value >= 500 && value <= 5000 {
                        return Some(value);
                    }
                }
            }
        }
        
        None
    }
}
