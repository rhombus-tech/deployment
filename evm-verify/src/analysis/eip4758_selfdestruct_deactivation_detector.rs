use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip4758SelfdestructDeactivationVulnerability {
    SelfdestructDependency { description: String, location: usize, confidence: f32 },
}

pub struct Eip4758SelfdestructDeactivationDetector {
    bytecode: Vec<u8>,
}

impl Eip4758SelfdestructDeactivationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip4758SelfdestructDeactivationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.uses_selfdestruct() {
            vulnerabilities.push(Eip4758SelfdestructDeactivationVulnerability::SelfdestructDependency {
                description: "Contract relies on SELFDESTRUCT which will be deactivated in EIP-4758".to_string(),
                location: 0,
                confidence: 0.95,
            });
        }
        
        vulnerabilities
    }
    
    fn uses_selfdestruct(&self) -> bool {
        self.bytecode.iter().any(|&b| b == 0xFF)
    }
}
