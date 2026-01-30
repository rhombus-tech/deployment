use serde::{Serialize, Deserialize};

/// GMX V2 Funding Rate Manipulation Detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GmxV2FundingRateManipulationVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
}

pub struct GmxV2FundingRateManipulationDetector {
    bytecode: Vec<u8>,
}

impl GmxV2FundingRateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GmxV2FundingRateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for funding rate calculations
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x04 { // DIV (rate calculation)
                let has_timestamp = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x42);
                
                if !has_timestamp {
                    vulnerabilities.push(GmxV2FundingRateManipulationVulnerability::Critical {
                        description: "Funding rate calculation without time component".to_string(),
                        location: i,
                    });
                    break;
                }
            }
        }
        
        vulnerabilities
    }
}
