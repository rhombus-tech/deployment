use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip7514ValidatorChurnBypassVulnerability {
    ChurnLimitExploit { description: String, location: usize, confidence: f32 },
}

pub struct Eip7514ValidatorChurnBypassDetector {
    bytecode: Vec<u8>,
}

impl Eip7514ValidatorChurnBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip7514ValidatorChurnBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_validator_queue_logic() && !self.validates_churn_limits() {
            vulnerabilities.push(Eip7514ValidatorChurnBypassVulnerability::ChurnLimitExploit {
                description: "Validator queue logic doesn't enforce EIP-7514 churn limits".to_string(),
                location: 0,
                confidence: 0.70,
            });
        }
        
        vulnerabilities
    }
    
    fn has_validator_queue_logic(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sload_count > 3 && add_count > 2
    }
    
    fn validates_churn_limits(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        lt_count > 2
    }
}
