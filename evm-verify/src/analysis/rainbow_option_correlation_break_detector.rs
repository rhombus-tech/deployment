use serde::{Deserialize, Serialize};

/// Rainbow Option: Multi-asset option (best-of, worst-of)
/// Attack: Break correlation assumptions

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RainbowOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RainbowOptionCorrelationBreakDetector {
    bytecode: Vec<u8>,
}

impl RainbowOptionCorrelationBreakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<RainbowOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unchecked_correlation_assumption() {
            vulnerabilities.push(RainbowOptionVulnerability {
                vulnerability_type: "Unchecked Multi-Asset Correlation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Rainbow option assumes correlation without validation".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_unchecked_correlation_assumption(&self) -> Option<usize> {
        // Multiple oracle calls for best-of/worst-of
        for i in 0..self.bytecode.len().saturating_sub(35) {
            let mut oracle_count = 0;
            for j in i..i+30.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xfa { oracle_count += 1; }
            }
            if oracle_count >= 2 { return Some(i); }
        }
        None
    }
}
