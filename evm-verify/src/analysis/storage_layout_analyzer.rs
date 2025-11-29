/// Storage Layout Vulnerability Analyzer
/// Beyond proxy - general storage issues: Packed storage bugs, storage slot overlap

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageVulnerabilityType {
    PackedStorageBug,
    StorageSlotOverlap,
    UninitializedStorage,
    StorageCollision,
    UnsafeStoragePointer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity { Critical, High, Medium, Low }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageVulnerability {
    pub vulnerability_type: StorageVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct StorageLayoutAnalyzer {
    bytecode: Vec<u8>,
}

impl StorageLayoutAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_packed_storage_bugs());
        vulnerabilities.extend(self.detect_storage_collisions());
        vulnerabilities.extend(self.detect_uninitialized_storage());
        vulnerabilities
    }

    fn detect_packed_storage_bugs(&self) -> Vec<StorageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x1b { // SHL (bit shifting for packing)
                let window = &self.bytecode[i..i.saturating_add(40).min(self.bytecode.len())];
                
                let has_mask = window.iter().any(|&op| op == 0x16); // AND (masking)
                let has_sstore = window.contains(&0x55);
                
                if has_sstore && !has_mask {
                    vulnerabilities.push(StorageVulnerability {
                        vulnerability_type: StorageVulnerabilityType::PackedStorageBug,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Packed storage write without proper masking. Can corrupt adjacent values.".to_string(),
                        remediation: "Mask before write: value = (slot & ~mask) | (newValue & mask)".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_storage_collisions(&self) -> Vec<StorageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 { // KECCAK256 (storage slot calculation)
                let window = &self.bytecode[i..i.saturating_add(30).min(self.bytecode.len())];
                
                let has_salt = window.windows(3).any(|w| {
                    w[0] == 0x60 && w[1] != 0x00 // PUSH1 with non-zero value (salt)
                });
                
                let has_namespace = window.iter().filter(|&&op| op == 0x60).count() > 1;
                
                if !has_salt && !has_namespace {
                    vulnerabilities.push(StorageVulnerability {
                        vulnerability_type: StorageVulnerabilityType::StorageCollision,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Storage slot calculation lacks unique namespace. Collision risk with other contracts.".to_string(),
                        remediation: "Use unique namespace: keccak256(abi.encode('MyContract.storage', key))".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_uninitialized_storage(&self) -> Vec<StorageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 { // SLOAD
                let before = &self.bytecode[i.saturating_sub(10)..i];
                let after = &self.bytecode[i..i.saturating_add(20).min(self.bytecode.len())];
                
                let has_zero_check = after.windows(3).any(|w| {
                    w[0] == 0x15 && // ISZERO (check if zero)
                    w[1] == 0x57    // JUMPI (handle uninitialized)
                });
                
                let in_critical_path = after.contains(&0xf1) || after.contains(&0xf4);
                
                if in_critical_path && !has_zero_check {
                    vulnerabilities.push(StorageVulnerability {
                        vulnerability_type: StorageVulnerabilityType::UninitializedStorage,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Storage read used without checking initialization. Uninitialized values can cause issues.".to_string(),
                        remediation: "Check initialization: require(value != 0, 'Uninitialized')".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_packed_storage_bug() {
        let bytecode = vec![0x1b, 0x55]; // SHL + SSTORE (no masking)
        let analyzer = StorageLayoutAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, StorageVulnerabilityType::PackedStorageBug)));
    }
}
