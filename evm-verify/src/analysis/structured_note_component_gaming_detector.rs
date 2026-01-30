use serde::{Deserialize, Serialize};

/// Structured Note: Combination of bond + derivatives
/// Attack: Exploit individual components

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredNoteVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StructuredNoteComponentGamingDetector {
    bytecode: Vec<u8>,
}

impl StructuredNoteComponentGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<StructuredNoteVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_component_isolation_issue() {
            vulnerabilities.push(StructuredNoteVulnerability {
                vulnerability_type: "Component Isolation Issue".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Individual components exploitable separately".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_component_isolation_issue(&self) -> Option<usize> {
        // Multiple pricing components
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let mut price_calcs = 0;
            for j in i..i+45.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xfa { price_calcs += 1; } // Oracle calls
            }
            if price_calcs >= 3 { return Some(i); }
        }
        None
    }
}
