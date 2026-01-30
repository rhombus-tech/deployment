use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticAssetRecursionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SyntheticAssetRecursiveLoopDetector {
    bytecode: Vec<u8>,
}

impl SyntheticAssetRecursiveLoopDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SyntheticAssetRecursionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_circular_synthetic_dependency() {
            vulnerabilities.push(SyntheticAssetRecursionVulnerability {
                vulnerability_type: "Circular Synthetic Asset Dependency".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Synthetic assets reference each other in a loop".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_circular_synthetic_dependency(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x54 { // SLOAD (read asset A)
                let mut has_call = false;
                let mut has_second_sload = false;
                for j in i+1..i+45.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xfa {
                        has_call = true;
                    }
                    if has_call && self.bytecode[j] == 0x54 {
                        has_second_sload = true;
                    }
                }
                if has_second_sload { return Some(i); }
            }
        }
        None
    }
}
