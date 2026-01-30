use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAssetCorrelationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MultiAssetCorrelationBreakDetector {
    bytecode: Vec<u8>,
}

impl MultiAssetCorrelationBreakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<MultiAssetCorrelationVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unchecked_correlation() {
            vulnerabilities.push(MultiAssetCorrelationVulnerability {
                vulnerability_type: "Multi-Asset Correlation Assumption Break".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Asset pair correlation assumed without validation".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_unchecked_correlation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle 1)
                if self.bytecode.get(i+15) == Some(&0xfa) { // oracle 2
                    return Some(i);
                }
            }
        }
        None
    }
}
