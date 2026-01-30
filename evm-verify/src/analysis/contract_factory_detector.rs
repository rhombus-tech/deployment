use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractFactoryVulnerability {
    Create2SaltPrediction { description: String, location: usize, confidence: f32 },
    DeterministicAddressExploit { description: String, location: usize, confidence: f32 },
    InitCodeInjection { description: String, location: usize, confidence: f32 },
    FactoryAccessControl { description: String, location: usize, confidence: f32 },
}

pub struct ContractFactoryDetector {
    bytecode: Vec<u8>,
}

impl ContractFactoryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ContractFactoryVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (i, window) in self.bytecode.windows(3).enumerate() {
            // CREATE2 detection (0xf5)
            if window[0] == 0xf5 {
                vulnerabilities.push(ContractFactoryVulnerability::Create2SaltPrediction {
                    description: "CREATE2 salt may be predictable".to_string(),
                    location: i,
                    confidence: 0.75,
                });
            }
            // CREATE detection (0xf0) 
            if window[0] == 0xf0 {
                vulnerabilities.push(ContractFactoryVulnerability::FactoryAccessControl {
                    description: "CREATE without access control".to_string(),
                    location: i,
                    confidence: 0.70,
                });
            }
        }
        
        vulnerabilities
    }
}
