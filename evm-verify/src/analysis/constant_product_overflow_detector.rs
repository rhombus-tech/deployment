use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantProductVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ConstantProductOverflowDetector {
    bytecode: Vec<u8>,
}

impl ConstantProductOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ConstantProductVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unprotected_product() {
            vulnerabilities.push(ConstantProductVulnerability {
                vulnerability_type: "Constant Product Overflow Risk".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "x*y product can overflow uint256".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_unprotected_product(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x02 { // MUL
                if self.bytecode.get(i+3) == Some(&0x02) { // MUL again (x*y)
                    return Some(i);
                }
            }
        }
        None
    }
}
