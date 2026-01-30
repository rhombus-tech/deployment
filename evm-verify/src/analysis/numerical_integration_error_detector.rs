use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumericalIntegrationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct NumericalIntegrationErrorDetector {
    bytecode: Vec<u8>,
}

impl NumericalIntegrationErrorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<NumericalIntegrationVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unbounded_integration_loop() {
            vulnerabilities.push(NumericalIntegrationVulnerability {
                vulnerability_type: "Unbounded Integration Loop".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Riemann sum or trapezoidal integration without step limit".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_unbounded_integration_loop(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop)
                let mut has_accumulation = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { has_accumulation = true; } // ADD (sum)
                }
                if has_accumulation { return Some(i); }
            }
        }
        None
    }
}
