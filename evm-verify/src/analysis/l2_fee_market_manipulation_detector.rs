use serde::{Deserialize, Serialize};

/// L2 Fee Market Manipulation: Manipulate L2 gas prices
/// Attack: Spam to drive up fees, then profit or DoS

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2FeeMarketVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct L2FeeMarketManipulationDetector {
    bytecode: Vec<u8>,
}

impl L2FeeMarketManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<L2FeeMarketVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_fee_manipulation_risk() {
            vulnerabilities.push(L2FeeMarketVulnerability {
                vulnerability_type: "L2 Fee Market Gaming".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Fee calculation vulnerable to manipulation".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_fee_manipulation_risk(&self) -> Option<usize> {
        // GASPRICE usage without anti-manipulation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x3a { // GASPRICE
                let mut has_bounds = false;
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 { // LT (max check)
                        has_bounds = true;
                    }
                }
                if !has_bounds { return Some(i); }
            }
        }
        None
    }
}
