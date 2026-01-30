use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateBloatDosVulnerability {
    UnboundedStorage { description: String, location: usize, confidence: f32 },
    NoStorageLimit { description: String, location: usize },
}

pub struct StateBloatDosDetector {
    bytecode: Vec<u8>,
}

impl StateBloatDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StateBloatDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Count SSTORE operations
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        
        // High number of sstores with no length checks suggests bloat risk
        if sstore_count > 50 && !self.has_storage_limits() {
            vulnerabilities.push(StateBloatDosVulnerability::UnboundedStorage {
                description: "Many storage writes without limits - state bloat DoS risk".to_string(),
                location: 0,
                confidence: 0.70,
            });
        }
        
        vulnerabilities
    }
    
    fn has_storage_limits(&self) -> bool {
        // Look for length checks (LT/GT comparisons)
        self.bytecode.iter().any(|&b| b == 0x10 || b == 0x11)
    }
}
