use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeModelVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FeeModelBreakingPointDetector {
    bytecode: Vec<u8>,
}

impl FeeModelBreakingPointDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<FeeModelVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unbounded_fee_calculation() {
            vulnerabilities.push(FeeModelVulnerability {
                vulnerability_type: "Fee Model Without Bounds".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Fee calculation lacks bounds, can reach breaking points".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_unbounded_fee_calculation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 { // MUL (fee calc)
                let mut has_cap = false;
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 { has_cap = true; }
                }
                if !has_cap { return Some(i); }
            }
        }
        None
    }
}
