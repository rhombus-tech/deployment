use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlotGrindingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StorageSlotGrindingDetector {
    bytecode: Vec<u8>,
}

impl StorageSlotGrindingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<StorageSlotGrindingVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_predictable_storage_slot() {
            vulnerabilities.push(StorageSlotGrindingVulnerability {
                vulnerability_type: "Predictable Storage Slot".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Storage slots can be precomputed and ground".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_predictable_storage_slot(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x20 { // SHA3 (slot calc)
                if self.bytecode.get(i+5) == Some(&0x55) { // SSTORE
                    return Some(i);
                }
            }
        }
        None
    }
}
