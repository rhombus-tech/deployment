use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageArrayBugVulnerability {
    VulnerableVersion { description: String, location: usize, confidence: f32 },
    DynamicArrayPush { description: String, location: usize },
}

pub struct StorageArrayBugDetector {
    bytecode: Vec<u8>,
}

impl StorageArrayBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageArrayBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Solidity 0.6.0-0.6.8 had storage array bugs
        // Detect dynamic array push operations
        if self.has_array_push_pattern() {
            vulnerabilities.push(StorageArrayBugVulnerability::DynamicArrayPush {
                description: "Dynamic array push detected - storage array bug risk (Solidity 0.6.0-0.6.8)".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_array_push_pattern(&self) -> bool {
        // Array push: SLOAD (get length) + ADD + SSTORE (update length) + SSTORE (push element)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 { // SLOAD
                let window = &self.bytecode[i..i.saturating_add(20).min(self.bytecode.len())];
                let has_add = window.iter().any(|&b| b == 0x01);
                let sstore_count = window.iter().filter(|&&b| b == 0x55).count();
                if has_add && sstore_count >= 2 {
                    return true;
                }
            }
        }
        false
    }
}
