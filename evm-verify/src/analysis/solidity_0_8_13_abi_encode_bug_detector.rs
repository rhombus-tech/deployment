use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solidity0813BugVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Solidity 0.8.13-0.8.16 ABI Encode Bug Detector
///
/// Detects the critical ABI encoding bug in Solidity versions 0.8.13 through 0.8.16
/// where calling abi.encodeCall with certain struct types could produce incorrect encoding.
///
/// CVE: Solidity Bug #13718
/// Impact: Data corruption in cross-contract calls, potential fund loss
/// Affected: Solidity 0.8.13, 0.8.14, 0.8.15, 0.8.16
/// Fixed: Solidity 0.8.17+
///
/// Detection Strategy:
/// - Identifies ABI encoding patterns with struct parameters
/// - Detects memory copying operations characteristic of buggy encoding
/// - Looks for CALLDATALOAD + MSTORE sequences used in struct encoding
/// - Checks for missing offset adjustments in nested struct encoding
pub struct Solidity0813AbiEncodeBugDetector;

impl Solidity0813AbiEncodeBugDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: ABI encoding with struct parameters
            // CODECOPY (0x39) followed by MLOAD (0x51) and CALLDATALOAD (0x35)
            if bytecode[i] == 0x39 {
                if self.has_struct_abi_encode_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Solidity 0.8.13-0.8.16 ABI encoding bug: Struct encoding may produce incorrect calldata leading to data corruption".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: abi.encodeCall with memory manipulation
            // KECCAK256 (0x20) for function selector followed by struct memory operations
            if bytecode[i] == 0x20 {
                if self.has_encode_call_struct_bug(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "abi.encodeCall with struct parameters detected: May be affected by Solidity 0.8.13-0.8.16 encoding bug".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 3: Nested struct encoding with missing offset adjustment
            // Multiple MLOAD operations without proper offset calculation
            if bytecode[i] == 0x51 {
                if self.has_nested_struct_encoding_issue(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Nested struct encoding detected: Vulnerable to offset calculation bug in Solidity 0.8.13-0.8.16".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<Solidity0813BugVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| Solidity0813BugVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_struct_abi_encode_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut has_mload = false;
        let mut has_calldataload = false;
        let mut has_mstore = false;
        let mut memory_ops = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x51 => has_mload = true, // MLOAD
                    0x35 => has_calldataload = true, // CALLDATALOAD
                    0x52 => {
                        has_mstore = true;
                        memory_ops += 1;
                    }
                    _ => {}
                }
            }
        }

        // Struct encoding requires multiple memory operations
        has_mload && has_calldataload && has_mstore && memory_ops >= 3
    }

    fn has_encode_call_struct_bug(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 45.min(bytecode.len().saturating_sub(pos));
        let mut has_function_selector = false;
        let mut has_struct_copy = false;
        let mut mstore_count = 0;

        // Check for function selector calculation
        if pos >= 4 {
            let lookback = 4.min(pos);
            for offset in 1..=lookback {
                if bytecode[pos - offset] == 0x63 { // PUSH4 (function selector)
                    has_function_selector = true;
                    break;
                }
            }
        }

        // Check for struct copying pattern
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x52 => mstore_count += 1, // MSTORE
                    0x39 => has_struct_copy = true, // CODECOPY
                    _ => {}
                }
            }
        }

        has_function_selector && has_struct_copy && mstore_count >= 2
    }

    fn has_nested_struct_encoding_issue(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut mload_count = 0;
        let mut add_count = 0;
        let mut has_offset_calc = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x51 => mload_count += 1, // MLOAD
                    0x01 => add_count += 1, // ADD
                    0x60..=0x7f => {
                        // PUSH operations for offset calculations
                        if add_count > 0 {
                            has_offset_calc = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Nested structs have multiple MLOAD operations
        // Bug manifests when offset calculations are incorrect
        mload_count >= 3 && (!has_offset_calc || add_count < mload_count - 1)
    }
}
