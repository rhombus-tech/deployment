use serde::{Deserialize, Serialize};

/// Protocol Version Mismatch: Old vs new version exploits
/// Attack: Interact with V1 and V2 to exploit differences

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolVersionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ProtocolVersionMismatchDetector {
    bytecode: Vec<u8>,
}

impl ProtocolVersionMismatchDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ProtocolVersionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_version_mismatch_risk() {
            vulnerabilities.push(ProtocolVersionVulnerability {
                vulnerability_type: "Protocol Version Mismatch Risk".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Calls to different protocol versions without consistency checks".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_version_mismatch_risk(&self) -> Option<usize> {
        // Multiple CALLs with version-like patterns (e.g., similar selectors)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let mut calls = Vec::new();
            for j in i..i+45.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xf1 {
                    calls.push(j);
                }
            }
            if calls.len() >= 2 { return Some(i); }
        }
        None
    }
}
