use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallbackReentrancyVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct CallbackReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CallbackReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CallbackReentrancyVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // Callback functions without reentrancy protection
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL (callback)
                let has_lock = self.bytecode[i.saturating_sub(10)..i]
                    .windows(2)
                    .any(|w| w[0] == 0x55); // SSTORE (lock variable)
                if !has_lock {
                    vulnerabilities.push(CallbackReentrancyVulnerability::Critical {
                        description: "Callback without reentrancy guard".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
