use serde::{Deserialize, Serialize};

/// Option Greeks: Delta, Gamma, Vega, Theta, Rho
/// Numerical derivatives of Black-Scholes are unstable

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreeksCalculationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GreeksCalculationErrorDetector {
    bytecode: Vec<u8>,
}

impl GreeksCalculationErrorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<GreeksCalculationVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_finite_difference_instability() {
            vulnerabilities.push(GreeksCalculationVulnerability {
                vulnerability_type: "Greeks Finite Difference Instability".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Numerical derivatives for Greeks unstable with small h".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_finite_difference_instability(&self) -> Option<usize> {
        // Pattern: (f(x+h) - f(x-h)) / 2h = central difference
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x03 && // SUB
               self.bytecode.get(i+5) == Some(&0x04) { // DIV
                return Some(i);
            }
        }
        None
    }
}
