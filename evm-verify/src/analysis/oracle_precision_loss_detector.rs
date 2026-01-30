use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OraclePrecisionLossVulnerability {
    PriceRoundsToZero { description: String, location: usize, confidence: f32 },
    DivisionBeforeMultiplication { description: String, location: usize },
}

pub struct OraclePrecisionLossDetector {
    bytecode: Vec<u8>,
}

impl OraclePrecisionLossDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OraclePrecisionLossVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // DIV
                if self.followed_by_mul(i) {
                    vulnerabilities.push(OraclePrecisionLossVulnerability::DivisionBeforeMultiplication {
                        description: "Oracle price: division before multiplication - precision loss".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn followed_by_mul(&self, div_location: usize) -> bool {
        let end = (div_location + 10).min(self.bytecode.len());
        self.bytecode[div_location..end].iter().any(|&b| b == 0x02)
    }
}
