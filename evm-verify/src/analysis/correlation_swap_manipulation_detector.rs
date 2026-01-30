use serde::{Deserialize, Serialize};

/// Correlation Swap: Pays realized correlation - strike correlation
/// Correlation = Cov(X,Y) / (σ_X × σ_Y)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSwapVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CorrelationSwapManipulationDetector {
    bytecode: Vec<u8>,
}

impl CorrelationSwapManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CorrelationSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_correlation_calculation_gaming() {
            vulnerabilities.push(CorrelationSwapVulnerability {
                vulnerability_type: "Correlation Calculation Gaming".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Realized correlation gameable via coordinated price manipulation".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_correlation_calculation_gaming(&self) -> Option<usize> {
        // Correlation needs two price streams
        for i in 0..self.bytecode.len().saturating_sub(40) {
            let mut oracle_calls = 0;
            for j in i..i+35.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xfa { // STATICCALL (oracle)
                    oracle_calls += 1;
                }
            }
            if oracle_calls >= 2 { // Two assets
                return Some(i);
            }
        }
        None
    }
}
