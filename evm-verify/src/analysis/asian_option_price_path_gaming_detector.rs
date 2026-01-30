use serde::{Deserialize, Serialize};

/// Asian Option: Payoff based on average price over period
/// Attack: Game which prices get included in average

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsianOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AsianOptionPricePathGamingDetector {
    bytecode: Vec<u8>,
}

impl AsianOptionPricePathGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<AsianOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_sampling_manipulation() {
            vulnerabilities.push(AsianOptionVulnerability {
                vulnerability_type: "Asian Option Sampling Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Price sampling schedule manipulatable".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_sampling_manipulation(&self) -> Option<usize> {
        // Average calculation in loop
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // Loop
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 && // ADD (sum prices)
                       self.bytecode.get(j+5) == Some(&0x04) { // DIV (average)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
