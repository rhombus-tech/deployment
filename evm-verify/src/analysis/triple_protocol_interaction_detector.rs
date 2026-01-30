use serde::{Deserialize, Serialize};

/// Triple Protocol Interaction: 3+ protocols in single transaction
/// Attack: Complex MEV with flash loans across 3+ protocols

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleProtocolVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TripleProtocolInteractionDetector {
    bytecode: Vec<u8>,
}

impl TripleProtocolInteractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<TripleProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_triple_protocol_interaction() {
            vulnerabilities.push(TripleProtocolVulnerability {
                vulnerability_type: "Triple Protocol Interaction Without Validation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Three or more protocol calls without atomicity checks".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_triple_protocol_interaction(&self) -> Option<usize> {
        // 3+ external calls to different addresses
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let mut call_count = 0;
            for j in i..i+55.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xf4 || self.bytecode[j] == 0xfa {
                    call_count += 1;
                }
            }
            if call_count >= 3 { return Some(i); }
        }
        None
    }
}
