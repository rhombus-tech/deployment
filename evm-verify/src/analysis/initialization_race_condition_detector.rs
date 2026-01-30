use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InitializationRaceConditionVulnerability {
    DoubleInitialize { description: String, location: usize, confidence: f32 },
    UnprotectedInitializer { description: String, location: usize },
    InitializerFrontrun { description: String, location: usize, confidence: f32 },
}

pub struct InitializationRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl InitializationRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InitializationRaceConditionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // initialize() selector: 0x8129fc1c (common)
        let initialize_selector = [0x81, 0x29, 0xfc, 0x1c];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == initialize_selector) {
                if !self.has_initialized_check(i, i + 80) {
                    vulnerabilities.push(InitializationRaceConditionVulnerability::UnprotectedInitializer {
                        description: "Initialize function without initialized flag check - can be called multiple times".to_string(),
                        location: i,
                    });
                }
                
                vulnerabilities.push(InitializationRaceConditionVulnerability::InitializerFrontrun {
                    description: "Initializer can be frontrun by attacker before legitimate owner".to_string(),
                    location: i,
                    confidence: 0.75,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_initialized_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for SLOAD (reading initialized flag) + ISZERO + JUMPI pattern
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_iszero = self.bytecode[start..range_end].iter().any(|&b| b == 0x15);
        has_sload && has_iszero
    }
}
