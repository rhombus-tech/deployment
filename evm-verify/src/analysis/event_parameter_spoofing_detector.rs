use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventParameterSpoofingVulnerability {
    UntrustedEventData { description: String, location: usize, confidence: f32 },
    MissingIndexing { description: String, location: usize },
}

pub struct EventParameterSpoofingDetector {
    bytecode: Vec<u8>,
}

impl EventParameterSpoofingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EventParameterSpoofingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // LOG0-LOG4 opcodes (0xA0-0xA4)
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] >= 0xA0 && self.bytecode[i] <= 0xA4 {
                // Check if event data comes from untrusted source (CALLDATALOAD)
                if self.has_calldataload_before(i, 20) {
                    vulnerabilities.push(EventParameterSpoofingVulnerability::UntrustedEventData {
                        description: "Event emits user-controlled data without validation - spoofing risk".to_string(),
                        location: i,
                        confidence: 0.70,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_calldataload_before(&self, location: usize, lookback: usize) -> bool {
        let start = location.saturating_sub(lookback);
        self.bytecode[start..location].iter().any(|&b| b == 0x35) // CALLDATALOAD
    }
}
