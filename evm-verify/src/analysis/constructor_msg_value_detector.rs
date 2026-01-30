use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstructorMsgValueVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct ConstructorMsgValueDetector {
    bytecode: Vec<u8>,
}

impl ConstructorMsgValueDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConstructorMsgValueVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern-based detection for constructor msg value
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for suspicious patterns
            if self.bytecode[i] == 0xf1 || // CALL
               self.bytecode[i] == 0xf4 || // DELEGATECALL
               self.bytecode[i] == 0x55 {  // SSTORE
                vulnerabilities.push(ConstructorMsgValueVulnerability::Medium {
                    description: "Potential vulnerability pattern detected".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
}
