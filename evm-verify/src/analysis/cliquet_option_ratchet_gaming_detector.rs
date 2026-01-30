use serde::{Deserialize, Serialize};

/// Cliquet Option: Ratchet mechanism locks in gains periodically
/// Attack: Game the reset dates

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliquetOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CliquetOptionRatchetGamingDetector {
    bytecode: Vec<u8>,
}

impl CliquetOptionRatchetGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CliquetOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_ratchet_timing_manipulation() {
            vulnerabilities.push(CliquetOptionVulnerability {
                vulnerability_type: "Ratchet Reset Timing Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Periodic reset vulnerable to price manipulation at boundary".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_ratchet_timing_manipulation(&self) -> Option<usize> {
        // Periodic reset: timestamp check + SSTORE
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 && // MOD (periodic)
                       self.bytecode.get(j+5) == Some(&0x55) { // SSTORE (lock)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
