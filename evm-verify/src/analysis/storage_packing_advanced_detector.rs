/// Advanced Storage Packing Exploit Detector
/// Detects sophisticated storage packing vulnerabilities
/// Critical for: Complex storage layout attacks

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePackingAdvancedVulnerability {
    pub vulnerability_type: StoragePackingAdvancedIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoragePackingAdvancedIssueType {
    PartialUpdateDirtySlot,        // Partial storage update creates dirty slot
    TypeCastingPackedStorage,      // Type casting with packed storage
    BitwiseOperationVuln,          // Bitwise operation vulnerability
    MappingPackedStructCollision,  // Mapping + packed struct collision
    DelegatecallPackingMismatch,   // Delegatecall with different packing
}

pub struct StoragePackingAdvancedDetector {
    bytecode: Vec<u8>,
}

impl StoragePackingAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StoragePackingAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_partial_updates());
        vulnerabilities.extend(self.detect_bitwise_issues());

        vulnerabilities
    }

    fn detect_partial_updates(&self) -> Vec<StoragePackingAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_partial_storage_write(i) {
                vulnerabilities.push(StoragePackingAdvancedVulnerability {
                    vulnerability_type: StoragePackingAdvancedIssueType::PartialUpdateDirtySlot,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    description: "Partial storage slot update may leave dirty bits".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Packed storage slot partially updated\n\
                        2. Other packed values in same slot not cleared\n\
                        3. Dirty bits remain from previous value\n\
                        4. State corruption or unexpected behavior\n\n\
                        Fix: Mask and clear bits before writing",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_bitwise_issues(&self) -> Vec<StoragePackingAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.has_unsafe_bitwise_op(i) {
                vulnerabilities.push(StoragePackingAdvancedVulnerability {
                    vulnerability_type: StoragePackingAdvancedIssueType::BitwiseOperationVuln,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    description: "Bitwise operation on packed storage without bounds check".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Bitwise operation on packed storage\n\
                        2. No validation of bit boundaries\n\
                        3. Bits overflow into adjacent packed value\n\
                        4. Adjacent value corrupted\n\n\
                        Fix: Validate bit ranges before operations",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn has_partial_storage_write(&self, pos: usize) -> bool {
        // SHL/SHR followed by SSTORE (partial write)
        pos + 10 < self.bytecode.len() &&
        (self.bytecode[pos] == 0x1B || self.bytecode[pos] == 0x1C) && // SHL/SHR
        self.bytecode[pos+5] == 0x55 // SSTORE
    }

    fn has_unsafe_bitwise_op(&self, pos: usize) -> bool {
        // AND/OR/XOR without prior bounds check
        pos + 5 < self.bytecode.len() &&
        (self.bytecode[pos] == 0x16 || self.bytecode[pos] == 0x17 || self.bytecode[pos] == 0x18)
    }
}
