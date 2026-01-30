use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReflectionTokenAccountingVulnerability {
    MissingSharesTracking { description: String, location: usize, confidence: f32 },
    DirectBalanceUse { description: String, location: usize },
    IncorrectReflectionCalc { description: String, location: usize },
}

pub struct ReflectionTokenAccountingDetector {
    bytecode: Vec<u8>,
}

impl ReflectionTokenAccountingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReflectionTokenAccountingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // balanceOf selector: 0x70a08231
        let balance_of = [0x70, 0xa0, 0x82, 0x31];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == balance_of) {
                // Check if using shares vs direct balance
                if !self.uses_shares_calculation(i, i + 80) {
                    vulnerabilities.push(ReflectionTokenAccountingVulnerability::DirectBalanceUse {
                        description: "Reflection token using direct balance instead of shares - accounting error".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn uses_shares_calculation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Shares calculation involves MUL and DIV for conversion
        let has_mul = self.bytecode[start..range_end].iter().any(|&b| b == 0x02);
        let has_div = self.bytecode[start..range_end].iter().any(|&b| b == 0x04);
        has_mul && has_div
    }
}
