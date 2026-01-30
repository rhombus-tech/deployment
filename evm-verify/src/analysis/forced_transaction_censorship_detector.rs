use serde::{Deserialize, Serialize};

/// Forced Transaction Censorship: Sequencer can censor force-inclusion
/// Attack: Block escape hatch transactions indefinitely

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForcedTransactionCensorshipVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ForcedTransactionCensorshipDetector {
    bytecode: Vec<u8>,
}

impl ForcedTransactionCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ForcedTransactionCensorshipVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_censorship_risk() {
            vulnerabilities.push(ForcedTransactionCensorshipVulnerability {
                vulnerability_type: "Forced Transaction Censorship Risk".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "No force-inclusion mechanism for censored transactions".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_censorship_risk(&self) -> Option<usize> {
        // Queue processing without force-inclusion fallback
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (queue)
                let mut has_timeout = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP (timeout check)
                        has_timeout = true;
                    }
                }
                if !has_timeout { return Some(i); }
            }
        }
        None
    }
}
