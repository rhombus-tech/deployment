use serde::{Serialize, Deserialize};

/// Balancer V3 Precision Loss Detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalancerV3PrecisionVulnerability {
    /// Critical: Precision loss in weighted math
    WeightedMathPrecisionLoss {
        description: String,
        location: usize,
    },
    /// High: Rounding errors in rate calculations
    RateCalculationRounding {
        description: String,
        location: usize,
    },
}

pub struct BalancerV3PrecisionDetector {
    bytecode: Vec<u8>,
}

impl BalancerV3PrecisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BalancerV3PrecisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for DIV operations without proper rounding
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // DIV
                let has_rounding = self.bytecode[i..std::cmp::min(i+10, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x01); // ADD (rounding up)
                
                if !has_rounding {
                    vulnerabilities.push(BalancerV3PrecisionVulnerability::WeightedMathPrecisionLoss {
                        description: "Division without rounding protection".to_string(),
                        location: i,
                    });
                    break;
                }
            }
        }
        
        vulnerabilities
    }
}
