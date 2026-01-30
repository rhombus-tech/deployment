/// MSTORE8 vs MSTORE Confusion Detector
///
/// Detects incorrect usage of MSTORE8 (write 1 byte) vs MSTORE (write 32 bytes).
/// Mixing these causes data corruption in assembly.
///
/// Why dangerous:
/// - MSTORE writes 32 bytes (full word)
/// - MSTORE8 writes only 1 byte
/// - Using wrong one = data corruption
/// - Silent failures in assembly
///
/// Real exploits:
/// - **$2M+ in assembly bugs**
/// - Data corruption in packed storage
/// - ABI encoding errors
/// - Memory layout breaks
///
/// Example:
/// ```solidity
/// assembly {
///     let ptr := mload(0x40)
///     // ❌ WRONG: Want to write full address but only writes 1 byte!
///     mstore8(ptr, someAddress)
///     
///     // ✓ CORRECT:
///     mstore(ptr, someAddress)
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MstoreConfusionVulnerability {
    pub vulnerability_type: MstoreIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MstoreIssueType {
    Mstore8ForLargeData,           // Using MSTORE8 for multi-byte data
    MstoreForSingleByte,           // Using MSTORE for single byte (gas waste)
    MixedStorePatterns,            // Mixing MSTORE and MSTORE8 unsafely
}

pub struct Mstore8ConfusionDetector {
    bytecode: Vec<u8>,
}

impl Mstore8ConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MstoreConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_mstore8_usage());

        vulnerabilities
    }

    fn detect_mstore8_usage(&self) -> Vec<MstoreConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x53 { // MSTORE8
                vulnerabilities.push(MstoreConfusionVulnerability {
                    vulnerability_type: MstoreIssueType::Mstore8ForLargeData,
                    severity: SecuritySeverity::Low,
                    confidence: 0.40,
                    description: "MSTORE8 usage detected - verify single-byte intent".to_string(),
                    exploit_scenario: format!(
                        "MSTORE8 at position {}:\n\
                        \n\
                        MSTORE8 writes only 1 byte. Verify this is intentional.\n\
                        Using MSTORE8 for multi-byte data causes corruption.\n\
                        \n\
                        DIFFERENCE:\n\
                        - MSTORE: Writes 32 bytes (0x52)\n\
                        - MSTORE8: Writes 1 byte (0x53)\n\
                        \n\
                        COMMON BUG:\n\
                        ```solidity\n\
                        assembly {{\n\
                            let ptr := mload(0x40)\n\
                            \n\
                            // ❌ WRONG: Only writes 1 byte!\n\
                            mstore8(ptr, someAddress)\n\
                            // Rest of address = garbage!\n\
                            \n\
                            // ✓ CORRECT:\n\
                            mstore(ptr, someAddress)\n\
                        }}\n\
                        ```",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }
}
