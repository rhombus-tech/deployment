use serde::{Deserialize, Serialize};

/// Cross-Layer Message Amplification: L1→L2 message triggers many L2 actions
/// Attack: Single L1 message causes DoS or cost explosion on L2

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLayerAmplificationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossLayerMessageAmplificationDetector {
    bytecode: Vec<u8>,
}

impl CrossLayerMessageAmplificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CrossLayerAmplificationVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_message_amplification() {
            vulnerabilities.push(CrossLayerAmplificationVulnerability {
                vulnerability_type: "Cross-Layer Message Amplification".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "L1 message triggers unbounded L2 operations".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_message_amplification(&self) -> Option<usize> {
        // Loop after message receipt without bounds
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (message data)
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x5b { // JUMPDEST (loop)
                        let mut has_bound = false;
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_bound = true;
                            }
                        }
                        if !has_bound { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
