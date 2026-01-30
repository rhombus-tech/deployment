use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageExhaustionVulnerability {
    UnboundedStorageGrowth { description: String, location: usize, confidence: f32 },
    NoStorageLimitCheck { description: String, location: usize },
    MappingGrowthUncontrolled { description: String, location: usize },
}

pub struct StorageExhaustionDetector {
    bytecode: Vec<u8>,
}

impl StorageExhaustionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageExhaustionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.stores_unbounded_data(i, i + 80) {
                vulnerabilities.push(StorageExhaustionVulnerability::UnboundedStorageGrowth {
                    description: "Storage writes without limit check - exhaustion DoS possible".to_string(),
                    location: i,
                    confidence: 0.75,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn stores_unbounded_data(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // SSTORE in loop without count limit
        let has_sstore_in_loop = self.bytecode[start..range_end]
            .windows(20)
            .any(|w| w.contains(&0x55) && w.contains(&0x57));
        
        has_sstore_in_loop
    }
}
