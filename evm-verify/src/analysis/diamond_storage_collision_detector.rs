use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiamondStorageCollisionVulnerability {
    StorageSlotCollision { description: String, location: usize, confidence: f32 },
    NoStorageNamespace { description: String, location: usize },
    UnstructuredStorageOverlap { description: String, location: usize },
}

pub struct DiamondStorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl DiamondStorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DiamondStorageCollisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Diamond pattern uses multiple facets with shared storage
        if self.has_diamond_pattern() && !self.uses_namespaced_storage() {
            vulnerabilities.push(DiamondStorageCollisionVulnerability::NoStorageNamespace {
                description: "Diamond proxy without namespaced storage - facet storage collision risk".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_diamond_pattern(&self) -> bool {
        // diamondCut selector: 0x1f931c1c
        self.bytecode.windows(4).any(|w| w == [0x1f, 0x93, 0x1c, 0x1c])
    }
    
    fn uses_namespaced_storage(&self) -> bool {
        // Namespaced storage uses keccak256 for slot calculation
        self.bytecode.iter().any(|&b| b == 0x20) // KECCAK256
    }
}
