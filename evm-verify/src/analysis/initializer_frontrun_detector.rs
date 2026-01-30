use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InitializerFrontrunVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct InitializerFrontrunDetector {
    bytecode: Vec<u8>,
}

impl InitializerFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InitializerFrontrunVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // Unprotected initializer functions
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for initialize function pattern
            if i + 4 < self.bytecode.len() && 
               self.bytecode[i] == 0x80 && self.bytecode[i+1] == 0x61 { // PUSH selector
                let has_initialized_check = self.bytecode[i+5..i+15]
                    .windows(2)
                    .any(|w| w[0] == 0x54 && w[1] == 0x15); // SLOAD, ISZERO
                if !has_initialized_check {
                    vulnerabilities.push(InitializerFrontrunVulnerability::High {
                        description: "Initializer without front-run protection".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
