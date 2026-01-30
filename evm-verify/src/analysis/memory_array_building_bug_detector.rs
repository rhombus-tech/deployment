use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryArrayBugVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Memory Array Building Bug Detector (Solidity <0.8.0)
///
/// Detects the memory array building bug in Solidity versions before 0.8.0
/// where dynamically building arrays in memory could lead to out-of-bounds writes.
///
/// CVE: Solidity Bug #11131
/// Impact: Memory corruption, potential for critical vulnerabilities
/// Affected: Solidity <0.8.0
/// Fixed: Solidity 0.8.0+
///
/// Detection Strategy:
/// - Identifies dynamic memory array construction patterns
/// - Detects loops with MSTORE operations without proper bounds checking
/// - Looks for memory allocation followed by unchecked array pushes
/// - Checks for missing length validation in array building
pub struct MemoryArrayBuildingBugDetector;

impl MemoryArrayBuildingBugDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Loop with MSTORE operations (potential array building)
            // JUMPDEST (0x5b) followed by memory operations
            if bytecode[i] == 0x5b {
                if self.has_unchecked_array_building_loop(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unchecked memory array building in loop: May cause out-of-bounds writes in Solidity <0.8.0".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: Dynamic memory allocation with array operations
            // MLOAD (0x51) with 0x40 (free memory pointer)
            if i + 1 < bytecode.len() && bytecode[i] == 0x60 && bytecode[i + 1] == 0x40 {
                if self.has_unsafe_dynamic_array_construction(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Dynamic memory array construction without bounds checking: Vulnerable to memory corruption".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 3: Array push operations without length validation
            // Multiple MSTORE operations with incrementing offsets
            if bytecode[i] == 0x52 {
                if self.has_unchecked_array_push_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Array push without length validation: May overflow in Solidity <0.8.0".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<MemoryArrayBugVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| MemoryArrayBugVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_unchecked_array_building_loop(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 60.min(bytecode.len().saturating_sub(pos));
        let mut has_mstore = false;
        let mut has_add = false;
        let mut has_jump = false;
        let mut mstore_count = 0;
        let mut has_bounds_check = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x52 => {
                        has_mstore = true;
                        mstore_count += 1;
                    }
                    0x01 => has_add = true, // ADD (offset increment)
                    0x56 | 0x57 => has_jump = true, // JUMP/JUMPI (loop)
                    0x10 | 0x11 => has_bounds_check = true, // LT/GT (bounds check)
                    _ => {}
                }
            }
        }

        // Loop with multiple MSTORE operations but no bounds checking
        has_mstore && has_add && has_jump && mstore_count >= 2 && !has_bounds_check
    }

    fn has_unsafe_dynamic_array_construction(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 50.min(bytecode.len().saturating_sub(pos));
        let mut has_mload = false;
        let mut has_mstore = false;
        let mut has_add = false;
        let mut mstore_count = 0;
        let mut has_revert = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x51 => has_mload = true, // MLOAD
                    0x52 => {
                        has_mstore = true;
                        mstore_count += 1;
                    }
                    0x01 => has_add = true, // ADD
                    0xfd => has_revert = true, // REVERT (bounds check)
                    _ => {}
                }
            }
        }

        // Memory allocation with multiple stores but no revert guard
        has_mload && has_mstore && has_add && mstore_count >= 3 && !has_revert
    }

    fn has_unchecked_array_push_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut mstore_sequence = 0;
        let mut has_increment = false;
        let mut has_length_check = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x52 => mstore_sequence += 1, // MSTORE
                    0x01 => has_increment = true, // ADD (index increment)
                    0x02 => has_increment = true, // MUL (offset calculation)
                    0x10 | 0x11 | 0x12 => has_length_check = true, // LT/GT/SLT
                    _ => {}
                }
            }
        }

        // Multiple sequential MSTORE operations with increment but no length validation
        mstore_sequence >= 2 && has_increment && !has_length_check
    }
}
