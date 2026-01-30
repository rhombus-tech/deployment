use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrecisionLossMultiplicationDivisionOrderVulnerability {
    DivisionBeforeMultiplication { description: String, location: usize, confidence: f32 },
    TruncationRisk { description: String, location: usize },
    RoundingErrorAmplification { description: String, location: usize },
}

pub struct PrecisionLossMultiplicationDivisionOrderDetector {
    bytecode: Vec<u8>,
}

impl PrecisionLossMultiplicationDivisionOrderDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PrecisionLossMultiplicationDivisionOrderVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect: a / b * c (loses precision) vs a * c / b (preserves precision)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x04 { // DIV
                // Check if followed by MUL within 5 opcodes
                for j in i+1..i.saturating_add(5).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL
                        vulnerabilities.push(PrecisionLossMultiplicationDivisionOrderVulnerability::DivisionBeforeMultiplication {
                            description: "Division before multiplication causes precision loss - should multiply first".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                        break;
                    }
                }
            }
        }
        
        vulnerabilities
    }
}
