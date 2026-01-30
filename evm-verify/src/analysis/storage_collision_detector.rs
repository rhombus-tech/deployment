use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageCollisionVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct StorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl StorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageCollisionVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // Storage collision in proxy patterns
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 && i > 2 { // SSTORE
                let slot = self.bytecode[i-2];
                if slot < 0x10 { // Low slots (< 16) often collision-prone
                    vulnerabilities.push(StorageCollisionVulnerability::High {
                        description: format!("Potential storage collision at slot {}", slot),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
