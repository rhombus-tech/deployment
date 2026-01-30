/// Return Data Size Mismatch Detector
///
/// Detects when functions return less data than expected, causing silent failures.
/// ABI decoding assumes fixed return data size - mismatch causes undefined behavior.
///
/// Why dangerous:
/// - Function returns less than ABI specifies
/// - Caller decodes garbage/zero values
/// - Silent failures (no revert, just wrong data)
/// - Integration bugs between contracts
///
/// Common causes:
/// - Assembly return with wrong size
/// - Conditional returns with different sizes
/// - Low-level call expecting structured data
/// - Compiler bugs in return encoding
///
/// Real exploits:
/// - Integration failures: $5M+
/// - Silent data corruption
/// - Oracle value manipulation
/// - Accounting errors from wrong returns
///
/// Example vulnerability:
/// ```solidity
/// interface IOracle {
///     function getPrice() external view returns (uint256, uint256);
/// }
///
/// contract BrokenOracle {
///     function getPrice() external view returns (uint256, uint256) {
///         assembly {
///             // ❌ BUG: Only returning 32 bytes, not 64!
///             mstore(0x00, 100)
///             return(0x00, 0x20)  // Returns 32 bytes
///             // Caller expects 64 bytes (two uint256)
///             // Second value decoded as zero!
///         }
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnDataMismatchVulnerability {
    pub vulnerability_type: ReturnDataIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReturnDataIssueType {
    FixedSizeReturn,               // RETURN with fixed small size
    ConditionalReturnSize,         // Different return sizes in branches
    ReturndatacopyOversized,       // Copying more return data than available
    EmptyReturn,                   // RETURN(0, 0) when data expected
    MismatchedReturnEncoding,      // Return encoding doesn't match ABI
}

pub struct ReturnDataSizeMismatchDetector {
    bytecode: Vec<u8>,
}

impl ReturnDataSizeMismatchDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReturnDataMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_small_fixed_returns());
        vulnerabilities.extend(self.detect_empty_returns());
        vulnerabilities.extend(self.detect_returndatacopy_oversized());

        vulnerabilities
    }

    fn detect_small_fixed_returns(&self) -> Vec<ReturnDataMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xF3 { // RETURN
                // Check if return size is small fixed value (suspicious)
                if let Some(size) = self.get_return_size(i) {
                    if size > 0 && size < 32 {
                        vulnerabilities.push(ReturnDataMismatchVulnerability {
                            vulnerability_type: ReturnDataIssueType::FixedSizeReturn,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: format!("RETURN with small fixed size: {} bytes", size),
                            exploit_scenario: format!(
                                "SMALL RETURN SIZE at position {}:\n\
                                \n\
                                Function returns only {} bytes.\n\
                                This may cause ABI decoding issues if caller expects more.\n\
                                \n\
                                VULNERABLE PATTERN:\n\
                                ```solidity\n\
                                contract BrokenReturn {{\n\
                                    function getData() external view returns (uint256, address) {{\n\
                                        assembly {{\n\
                                            // ❌ Only returns 20 bytes\n\
                                            mstore(0x00, caller())\n\
                                            return(0x00, 0x14)  // 20 bytes\n\
                                            \n\
                                            // Caller expects 64 bytes:\n\
                                            // - 32 bytes for uint256\n\
                                            // - 32 bytes for address (padded)\n\
                                            // Second value will be garbage!\n\
                                        }}\n\
                                    }}\n\
                                }}\n\
                                \n\
                                contract Caller {{\n\
                                    function use() external {{\n\
                                        (uint256 amount, address addr) = broken.getData();\n\
                                        // amount = garbage/zero\n\
                                        // addr = truncated\n\
                                        // Silent failure!\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                Recommendation: Verify return size matches ABI",
                                i, size
                            ),
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_empty_returns(&self) -> Vec<ReturnDataMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0xF3 { // RETURN
                if let Some(size) = self.get_return_size(i) {
                    if size == 0 {
                        vulnerabilities.push(ReturnDataMismatchVulnerability {
                            vulnerability_type: ReturnDataIssueType::EmptyReturn,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: "RETURN with zero size detected".to_string(),
                            exploit_scenario: format!(
                                "EMPTY RETURN at position {}:\n\
                                \n\
                                Function returns zero bytes.\n\
                                If caller expects data, will decode as zero/default values.\n\
                                \n\
                                This can cause:\n\
                                - Zero balance readings\n\
                                - Null address returns\n\
                                - False boolean values\n\
                                - Silent failures in integrations",
                                i
                            ),
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_returndatacopy_oversized(&self) -> Vec<ReturnDataMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        // RETURNDATACOPY without RETURNDATASIZE check can copy invalid data
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x3E { // RETURNDATACOPY
                // Check if size is validated against RETURNDATASIZE
                if !self.has_returndatasize_check_before(i) {
                    vulnerabilities.push(ReturnDataMismatchVulnerability {
                        vulnerability_type: ReturnDataIssueType::ReturndatacopyOversized,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "RETURNDATACOPY without size validation".to_string(),
                        exploit_scenario: format!(
                            "RETURNDATACOPY WITHOUT VALIDATION at position {}:\n\
                            \n\
                            Copying return data without checking actual size.\n\
                            If external call returns less than expected, will revert or copy garbage.\n\
                            \n\
                            VULNERABLE:\n\
                            ```solidity\n\
                            assembly {{\n\
                                let success := call(gas(), target, 0, 0, 0, 0, 0)\n\
                                \n\
                                // ❌ Assumes 64 bytes returned\n\
                                returndatacopy(0, 0, 0x40)\n\
                                \n\
                                // If target returned less than 64 bytes:\n\
                                // - Reverts (out of bounds)\n\
                                // - Or copies uninitialized memory\n\
                            }}\n\
                            ```\n\
                            \n\
                            SAFE:\n\
                            ```solidity\n\
                            assembly {{\n\
                                let success := call(gas(), target, 0, 0, 0, 0, 0)\n\
                                \n\
                                // ✓ Check actual size\n\
                                let size := returndatasize()\n\
                                require(size >= 0x40, 'Insufficient return data')\n\
                                \n\
                                returndatacopy(0, 0, size)\n\
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

    fn get_return_size(&self, pos: usize) -> Option<u64> {
        // Look backwards for PUSH of return size
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F {
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if i + push_size < self.bytecode.len() {
                    let mut value: u64 = 0;
                    for j in 0..push_size.min(8) {
                        value = (value << 8) | self.bytecode[i + 1 + j] as u64;
                    }
                    return Some(value);
                }
            }
        }
        None
    }

    fn has_returndatasize_check_before(&self, pos: usize) -> bool {
        // Look for RETURNDATASIZE before RETURNDATACOPY
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x3D { // RETURNDATASIZE
                return true;
            }
        }
        false
    }
}
