use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyPauseBypassVulnerability {
    /// Critical security issue detected
    Critical {
        description: String,
        location: usize,
    },
    /// High severity issue
    High {
        description: String,
        location: usize,
    },
    /// Medium severity issue
    Medium {
        description: String,
        location: usize,
    },
}

pub struct EmergencyPauseBypassDetector {
    bytecode: Vec<u8>,
}

impl EmergencyPauseBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EmergencyPauseBypassVulnerability> {
        
        // Detect missing pause checks in critical functions
        let mut vulnerabilities = Vec::new();
        
        // Look for state-changing functions without pause checks
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE (state change)
                // Check if there's a pause check before this
                let has_pause_check = self.bytecode[i.saturating_sub(10)..i]
                    .windows(2)
                    .any(|w| (w[0] == 0x54 && w[1] == 0x15) || // SLOAD, ISZERO
                             (w[0] == 0x15 && w[1] == 0x57));  // ISZERO, JUMPI
                
                if !has_pause_check {
                    vulnerabilities.push(EmergencyPauseBypassVulnerability::Medium {
                        description: "State change without pause modifier check".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    
    }
}
