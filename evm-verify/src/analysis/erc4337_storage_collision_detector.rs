use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc4337StorageCollisionVulnerability {
    AAStorageCollision { description: String, location: usize, confidence: f32 },
    UnstructuredStorageOverlap { description: String, location: usize },
    ValidationStorageConflict { description: String, location: usize },
}

pub struct Erc4337StorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl Erc4337StorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc4337StorageCollisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if !self.uses_eip1967_storage() && self.has_aa_validation() {
            vulnerabilities.push(Erc4337StorageCollisionVulnerability::AAStorageCollision {
                description: "ERC-4337 account abstraction without EIP-1967 storage - collision risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_validation_function(i) {
                if self.uses_regular_storage_in_validation(i, i + 100) {
                    vulnerabilities.push(Erc4337StorageCollisionVulnerability::ValidationStorageConflict {
                        description: "validateUserOp uses regular storage slots - may collide with implementation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn uses_eip1967_storage(&self) -> bool {
        // EIP-1967 uses specific storage slots with keccak256 hashing
        // Look for: keccak256("...") - 1 pattern
        self.bytecode.windows(3).any(|w| {
            w[0] == 0x20 && w[2] == 0x03 // KECCAK256 + SUB
        })
    }
    
    fn has_aa_validation(&self) -> bool {
        // validateUserOp selector: 0x3a871cdd
        self.bytecode.windows(4).any(|w| w == [0x3a, 0x87, 0x1c, 0xdd])
    }
    
    fn is_validation_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0x3a, 0x87, 0x1c, 0xdd])
    }
    
    fn uses_regular_storage_in_validation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Regular SLOAD without keccak256-based slot calculation
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_keccak = self.bytecode[start..range_end].iter().any(|&b| b == 0x20);
        has_sload && !has_keccak
    }
}
