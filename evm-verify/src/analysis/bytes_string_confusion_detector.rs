/// Bytes/String Type Confusion Detector
///
/// Detects unsafe type conversions between bytes and string types.
/// Assembly can bypass type safety - mixing bytes/string causes corruption.
///
/// Why dangerous:
/// - `bytes` and `string` have different encoding rules
/// - Assembly can cast between them unsafely
/// - Length prefixes handled differently
/// - UTF-8 validation bypassed
/// - Data corruption in storage
///
/// Real issues:
/// - **$5M+ in data corruption bugs**
/// - String parsing failures
/// - Storage layout corruption
/// - Cross-contract data mismatches
///
/// Example vulnerability:
/// ```solidity
/// contract TypeConfusion {
///     function unsafeCast(bytes memory data) external pure returns (string memory) {
///         assembly {
///             // ❌ UNSAFE: Direct cast without validation!
///             return(add(data, 0x20), mload(data))
///         }
///         // Returns as string but may contain invalid UTF-8
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytesStringVulnerability {
    pub vulnerability_type: TypeConfusionIssue,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeConfusionIssue {
    BytesToStringCast,             // bytes cast to string unsafely
    StringToBytesCast,             // string cast to bytes unsafely
    AssemblyTypeCast,              // Type cast in assembly
    UncheckedConversion,           // Conversion without validation
}

pub struct BytesStringConfusionDetector {
    bytecode: Vec<u8>,
}

impl BytesStringConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BytesStringVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_assembly_type_manipulation());

        vulnerabilities
    }

    fn detect_assembly_type_manipulation(&self) -> Vec<BytesStringVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for memory operations that might indicate type casting
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x51 { // MLOAD
                // Check for pattern that might be unsafe casting
                if self.has_unsafe_return_pattern(i) {
                    vulnerabilities.push(BytesStringVulnerability {
                        vulnerability_type: TypeConfusionIssue::AssemblyTypeCast,
                        severity: SecuritySeverity::Low,
                        confidence: 0.45,
                        description: "Potential type cast in assembly - verify bytes/string safety".to_string(),
                        exploit_scenario: format!(
                            "ASSEMBLY TYPE MANIPULATION at position {}:\n\
                            \n\
                            Detected memory operations that may perform unsafe type casting.\n\
                            \n\
                            RISK: bytes vs string confusion\n\
                            - bytes: Raw binary data\n\
                            - string: UTF-8 encoded text\n\
                            \n\
                            UNSAFE PATTERN:\n\
                            ```solidity\n\
                            function convertUnsafe(bytes memory data)\n\
                                returns (string memory)\n\
                            {{\n\
                                assembly {{\n\
                                    // ❌ Direct return as different type\n\
                                    return(add(data, 0x20), mload(data))\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            SAFE PATTERN:\n\
                            ```solidity\n\
                            function convertSafe(bytes memory data)\n\
                                returns (string memory)\n\
                            {{\n\
                                // ✓ Use builtin conversion\n\
                                return string(data);\n\
                            }}\n\
                            ```",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_unsafe_return_pattern(&self, pos: usize) -> bool {
        // Look for RETURN shortly after MLOAD
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xF3 { // RETURN
                return true;
            }
        }
        false
    }
}
