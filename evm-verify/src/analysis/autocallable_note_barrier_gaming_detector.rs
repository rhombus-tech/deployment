use serde::{Deserialize, Serialize};

/// Autocallable: Early redemption if barrier hit
/// Attack: Force/prevent autocall

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutocallableNoteVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AutocallableNoteBarrierGamingDetector {
    bytecode: Vec<u8>,
}

impl AutocallableNoteBarrierGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<AutocallableNoteVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_autocall_trigger_manipulation() {
            vulnerabilities.push(AutocallableNoteVulnerability {
                vulnerability_type: "Autocall Trigger Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Autocall barrier can be manipulated for early redemption".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_autocall_trigger_manipulation(&self) -> Option<usize> {
        // Autocall: periodic barrier check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (periodic check)
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 { // GT (barrier)
                        let mut has_averaging = false;
                        for k in i..j {
                            if self.bytecode[k] == 0x04 { has_averaging = true; }
                        }
                        if !has_averaging { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
