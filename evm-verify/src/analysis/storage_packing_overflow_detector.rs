use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoragePackingOverflowVulnerability {
    BitfieldOverflow { description: String, location: usize, confidence: f32 },
}

pub struct StoragePackingOverflowDetector {
    bytecode: Vec<u8>,
}

impl StoragePackingOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StoragePackingOverflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_storage_packing() && !self.validates_packed_values() {
            vulnerabilities.push(StoragePackingOverflowVulnerability::BitfieldOverflow {
                description: "Storage packing without overflow validation - bitfield overflow risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_storage_packing(&self) -> bool {
        let shl_count = self.bytecode.iter().filter(|&&b| b == 0x1B).count();
        let and_count = self.bytecode.iter().filter(|&&b| b == 0x16).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        shl_count > 2 && and_count > 2 && sstore_count > 0
    }
    
    fn validates_packed_values(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gt_count > 2
    }
}
