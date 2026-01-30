use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SequencerCensorshipVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct SequencerCensorshipDetector {
    bytecode: Vec<u8>,
}

impl SequencerCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SequencerCensorshipVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern-based detection for sequencer censorship
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for suspicious patterns
            if self.bytecode[i] == 0xf1 || // CALL
               self.bytecode[i] == 0xf4 || // DELEGATECALL
               self.bytecode[i] == 0x55 {  // SSTORE
                vulnerabilities.push(SequencerCensorshipVulnerability::Medium {
                    description: "Potential vulnerability pattern detected".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
}
