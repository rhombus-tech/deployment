use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIEncodingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ABIEncodingEdgeCaseDetector {
    bytecode: Vec<u8>,
}

impl ABIEncodingEdgeCaseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ABIEncodingVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_unchecked_abi_decode() {
            vulnerabilities.push(ABIEncodingVulnerability {
                vulnerability_type: "Unchecked ABI Decode".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "ABI decoding without length/bounds validation".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_unchecked_abi_decode(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                let mut has_bounds_check = false;
                for j in (i+1)..(i+10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                        has_bounds_check = true;
                    }
                }
                if !has_bounds_check { return Some(i); }
            }
        }
        None
    }
}
