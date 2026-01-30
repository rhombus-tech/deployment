use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloatingPointEmulationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FloatingPointEmulationDetector {
    bytecode: Vec<u8>,
}

impl FloatingPointEmulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<FloatingPointEmulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_exponent_mantissa_separation() {
            vulnerabilities.push(FloatingPointEmulationVulnerability {
                vulnerability_type: "Float Emulation Precision Loss".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Separating exponent/mantissa loses precision".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_exponent_mantissa_separation(&self) -> Option<usize> {
        // Pattern: Shifts (for exponent) + mask (for mantissa)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x1c { // SHR (extract exponent)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x16 { // AND (mask mantissa)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
