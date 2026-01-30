use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ElementFixedRatesVulnerability {
    pub location: usize,
    pub confidence: f32,
    pub vulnerability_type: String,
    pub description: String,
}

pub struct ElementFixedRatesDetector {
    bytecode: Vec<u8>,
}

impl ElementFixedRatesDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ElementFixedRatesVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for maturity validation
        if let Some(location) = self.find_maturity_issue() {
            vulnerabilities.push(ElementFixedRatesVulnerability {
                location,
                confidence: 0.78,
                vulnerability_type: "MaturityRolloverRisk".to_string(),
                description: "Fixed-rate term lacks proper maturity timestamp validation".to_string(),
            });
        }
        
        // Check for yield calculation validation
        if let Some(location) = self.find_yield_calculation_issue() {
            vulnerabilities.push(ElementFixedRatesVulnerability {
                location,
                confidence: 0.75,
                vulnerability_type: "ImpliedAPYCalculationFlaw".to_string(),
                description: "Yield calculation lacks proper validation and overflow protection".to_string(),
            });
        }
        
        vulnerabilities
    }

    fn find_maturity_issue(&self) -> Option<usize> {
        // Look for storage operations without timestamp checks
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let has_timestamp = self.bytecode[i.saturating_sub(10)..i]
                    .windows(2)
                    .any(|w| w[0] == 0x42 && w[1] == 0x11); // TIMESTAMP + GT
                
                if !has_timestamp {
                    return Some(i);
                }
            }
        }
        None
    }

    fn find_yield_calculation_issue(&self) -> Option<usize> {
        // Look for division operations without overflow checks
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x04 { // DIV
                let has_validation = self.bytecode[i.saturating_sub(5)..i]
                    .contains(&0x11); // GT check before DIV
                
                if !has_validation {
                    return Some(i);
                }
            }
        }
        None
    }
}
