use serde::{Deserialize, Serialize};

/// Caplet: Cap on interest rate (max(rate - strike, 0))
/// Floorlet: Floor on interest rate (max(strike - rate, 0))

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapletFloorletVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CapletFloorletStrikeGamingDetector {
    bytecode: Vec<u8>,
}

impl CapletFloorletStrikeGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CapletFloorletVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_rate_manipulation() {
            vulnerabilities.push(CapletFloorletVulnerability {
                vulnerability_type: "Interest Rate Reference Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Reference rate source manipulatable".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_rate_manipulation(&self) -> Option<usize> {
        // Rate check without TWAP
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // Rate oracle
                let mut has_averaging = false;
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { has_averaging = true; } // DIV for average
                }
                if !has_averaging { return Some(i); }
            }
        }
        None
    }
}
