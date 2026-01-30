use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidityProofBypassVulnerability {
    ProofNotVerified { description: String, location: usize },
    BypassViaFallback { description: String, location: usize },
    OptionalVerification { description: String, location: usize },
}

pub struct ValidityProofBypassDetector {
    bytecode: Vec<u8>,
}

impl ValidityProofBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ValidityProofBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.is_state_transition(i) && !self.requires_proof_verification(i, i + 80) {
                vulnerabilities.push(ValidityProofBypassVulnerability::ProofNotVerified {
                    description: "State transition without mandatory proof verification".to_string(),
                    location: i,
                });
            }
        }
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.has_verification_bypass(i, i + 60) {
                vulnerabilities.push(ValidityProofBypassVulnerability::BypassViaFallback {
                    description: "Proof verification can be bypassed via fallback mechanism".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn is_state_transition(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        self.bytecode[location..location + 20].iter().any(|&b| b == 0x55) // SSTORE
    }
    
    fn requires_proof_verification(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].windows(2).any(|w| w[0] == 0x60 && w[1] == 0x08) // Pairing check
    }
    
    fn has_verification_bypass(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for OR logic that might bypass verification
        self.bytecode[start..range_end].iter().any(|&b| b == 0x17) // OR
    }
}
