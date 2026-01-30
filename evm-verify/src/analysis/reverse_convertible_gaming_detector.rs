use serde::{Deserialize, Serialize};

/// Reverse Convertible: Converts to stock if below strike
/// Attack: Force conversion by pushing price down

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseConvertibleVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ReverseConvertibleGamingDetector {
    bytecode: Vec<u8>,
}

impl ReverseConvertibleGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ReverseConvertibleVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_conversion_trigger_manipulation() {
            vulnerabilities.push(ReverseConvertibleVulnerability {
                vulnerability_type: "Conversion Trigger Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Conversion price threshold manipulatable".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_conversion_trigger_manipulation(&self) -> Option<usize> {
        // Conversion: price < strike check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // Price oracle
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 { // LT (below strike)
                        let mut has_protection = false;
                        for k in i..j {
                            if self.bytecode[k] == 0x42 { has_protection = true; } // Time-based
                        }
                        if !has_protection { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
