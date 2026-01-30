use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WormholeGuardianManipulationVulnerability {
    GuardianSetUpdateable { description: String, location: usize, confidence: f32 },
    InsufficientGuardianQuorum { description: String, location: usize },
    GuardianSignatureNotValidated { description: String, location: usize },
}

pub struct WormholeGuardianManipulationDetector {
    bytecode: Vec<u8>,
}

impl WormholeGuardianManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WormholeGuardianManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.verifies_guardian_signatures(i, i + 100) {
                if !self.checks_quorum_threshold(i, i + 100) {
                    vulnerabilities.push(WormholeGuardianManipulationVulnerability::InsufficientGuardianQuorum {
                        description: "Guardian signature verification without proper quorum check".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn verifies_guardian_signatures(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Multiple ecrecover calls (guardian signatures)
        let ecrecover_count = self.bytecode[start..range_end]
            .windows(2)
            .filter(|w| w[0] == 0x60 && w[1] == 0x01)
            .count();
        
        ecrecover_count >= 2
    }
    
    fn checks_quorum_threshold(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Must count signatures and compare to threshold
        let has_counter = self.bytecode[start..range_end].iter().any(|&b| b == 0x01); // ADD
        let has_threshold_check = self.bytecode[start..range_end]
            .windows(2)
            .any(|w| (w[0] == 0x10 || w[0] == 0x11) && w[1] == 0xFD);
        
        has_counter && has_threshold_check
    }
}
