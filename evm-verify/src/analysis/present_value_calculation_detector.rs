use serde::{Deserialize, Serialize};

/// Present Value: PV = FV / (1 + r)^n
/// Discount rate and time errors compound

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentValueVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PresentValueCalculationDetector {
    bytecode: Vec<u8>,
}

impl PresentValueCalculationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<PresentValueVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_discount_rate_precision_loss() {
            vulnerabilities.push(PresentValueVulnerability {
                vulnerability_type: "Discount Rate Precision Loss".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "PV discount calculation loses precision over time".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_discount_rate_precision_loss(&self) -> Option<usize> {
        // Pattern: DIV + EXP (discount factor)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x04 { // DIV
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x0a { // EXP
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
