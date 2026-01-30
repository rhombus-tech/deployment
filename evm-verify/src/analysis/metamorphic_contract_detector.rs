use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetamorphicContractVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct MetamorphicContractDetector {
    bytecode: Vec<u8>,
}

impl MetamorphicContractDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MetamorphicContractVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // CREATE2 with SELFDESTRUCT (metamorphic pattern)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf5 { // CREATE2
                let has_selfdestruct = self.bytecode.iter().any(|&b| b == 0xff);
                if has_selfdestruct {
                    vulnerabilities.push(MetamorphicContractVulnerability::Critical {
                        description: "Metamorphic contract detected: CREATE2 + SELFDESTRUCT".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
