use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerpFundingArbitrageDetectorVulnerability {
    FundingRateManipulation { description: String, location: usize },
}

pub struct PerpFundingArbitrageDetector { bytecode: Vec<u8> }

impl PerpFundingArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<PerpFundingArbitrageDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x04 && i > 10 { // DIV in funding calc
                let uses_timestamp = self.bytecode[i-10..i].iter().any(|&b| b == 0x42);
                if !uses_timestamp {
                    vulnerabilities.push(PerpFundingArbitrageDetectorVulnerability::FundingRateManipulation {
                        description: "Funding rate without time component".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}