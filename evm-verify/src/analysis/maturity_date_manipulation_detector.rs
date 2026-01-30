use serde::{Deserialize, Serialize};

/// Maturity Date Manipulation: Financial instruments with maturity dates
/// Attack: Manipulate conditions before/at maturity

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaturityDateVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MaturityDateManipulationDetector {
    bytecode: Vec<u8>,
}

impl MaturityDateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<MaturityDateVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_maturity_manipulation_risk() {
            vulnerabilities.push(MaturityDateVulnerability {
                vulnerability_type: "Maturity Date Manipulation Risk".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Maturity settlement vulnerable to last-block manipulation".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_maturity_manipulation_risk(&self) -> Option<usize> {
        // Maturity: timestamp >= maturity date without averaging
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x14 { // GT/EQ (maturity)
                        let mut has_price_averaging = false;
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x04 { // DIV (averaging)
                                has_price_averaging = true;
                            }
                        }
                        if !has_price_averaging { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
