use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyStopMissingVulnerability {
    NoPauseMechanism { description: String, location: usize, confidence: f32 },
    CriticalFunctionsNotPausable { description: String, location: usize },
}

pub struct EmergencyStopMissingDetector {
    bytecode: Vec<u8>,
}

impl EmergencyStopMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EmergencyStopMissingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_critical_functions() {
            if !self.has_pause_mechanism() {
                vulnerabilities.push(EmergencyStopMissingVulnerability::NoPauseMechanism {
                    description: "Contract with critical functions but no pause/emergency stop".to_string(),
                    location: 0,
                    confidence: 0.75,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_critical_functions(&self) -> bool {
        // transfer, withdraw, swap, etc.
        let transfer = [0xa9, 0x05, 0x9c, 0xbb];
        let withdraw = [0x2e, 0x1a, 0x7d, 0x4d];
        
        self.bytecode.windows(4).any(|w| w == transfer || w == withdraw)
    }
    
    fn has_pause_mechanism(&self) -> bool {
        // pause() selector: 0x8456cb59
        // paused() selector: 0x5c975abb
        let pause = [0x84, 0x56, 0xcb, 0x59];
        let paused = [0x5c, 0x97, 0x5a, 0xbb];
        
        self.bytecode.windows(4).any(|w| w == pause || w == paused)
    }
}
