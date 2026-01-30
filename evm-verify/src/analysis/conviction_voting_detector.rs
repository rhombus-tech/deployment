use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConvictionVotingVulnerability {
    ConvictionManipulation { description: String, location: usize, confidence: f32 },
    VotingPowerAccumulation { description: String, location: usize, confidence: f32 },
    ProposalSpamming { description: String, location: usize, confidence: f32 },
    ConvictionDecayExploit { description: String, location: usize, confidence: f32 },
}

pub struct ConvictionVotingDetector {
    bytecode: Vec<u8>,
}

impl ConvictionVotingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConvictionVotingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (i, window) in self.bytecode.windows(3).enumerate() {
            // Check for voting-related opcodes
            if window[0] == 0x54 && window[1] == 0x55 { // SLOAD + SSTORE
                vulnerabilities.push(ConvictionVotingVulnerability::ConvictionManipulation {
                    description: "Conviction voting state may be manipulable".to_string(),
                    location: i,
                    confidence: 0.70,
                });
            }
        }
        
        vulnerabilities
    }
}
