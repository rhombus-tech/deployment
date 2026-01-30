use serde::{Deserialize, Serialize};

/// Compound Interest: A = P(1 + r/n)^(nt)
/// Small errors compound exponentially over time

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundInterestVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CompoundInterestCalculationErrorDetector {
    bytecode: Vec<u8>,
}

impl CompoundInterestCalculationErrorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CompoundInterestVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unbounded_exponentiation() {
            vulnerabilities.push(CompoundInterestVulnerability {
                vulnerability_type: "Unbounded Compound Interest Exponentiation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Compound interest exponent lacks overflow protection".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_unbounded_exponentiation(&self) -> Option<usize> {
        // Pattern: Loop for exponentiation (a^n) without bounds
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x5b { // JUMPDEST
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (repeated for power)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
