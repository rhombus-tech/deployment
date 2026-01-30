use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposerBuilderCollusionVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct ProposerBuilderCollusionDetector {
    bytecode: Vec<u8>,
}

impl ProposerBuilderCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProposerBuilderCollusionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern-based detection for proposer builder collusion
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for suspicious patterns
            if self.bytecode[i] == 0xf1 || // CALL
               self.bytecode[i] == 0xf4 || // DELEGATECALL
               self.bytecode[i] == 0x55 {  // SSTORE
                vulnerabilities.push(ProposerBuilderCollusionVulnerability::Medium {
                    description: "Potential vulnerability pattern detected".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
}
