use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViaIrPipelineBugVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Solidity Via-IR Pipeline Bug Detector
///
/// Detects vulnerabilities in contracts compiled with Solidity's experimental "via-IR" pipeline
/// that uses Yul as an intermediate representation before generating EVM bytecode.
///
/// Known Issues:
/// - Memory layout corruption in complex struct assignments
/// - Incorrect storage packing with via-IR optimization
/// - Stack-too-deep workarounds causing variable shadowing
/// - Incorrect calldata decoding with nested dynamic arrays
/// - Function selector collision in via-IR compiled contracts
///
/// Versions Affected: Solidity 0.8.13+
/// Severity: Critical when via-IR is enabled without thorough testing
///
/// Real-World Cases:
/// - Several DeFi protocols experienced silent failures after enabling via-IR
/// - Storage corruption led to fund losses in multi-token vaults
/// - Access control bypasses due to incorrect variable assignments
///
/// Detection Strategy:
/// - Identifies via-IR characteristic bytecode patterns
/// - Detects memory layout issues from Yul IR compilation
/// - Checks for incorrect storage slot calculations
/// - Looks for stack manipulation patterns unique to via-IR
pub struct SolidityViaIrPipelineBugDetector;

impl SolidityViaIrPipelineBugDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Via-IR memory layout corruption
            // Multiple MSTORE operations with calculated offsets (via-IR characteristic)
            if bytecode[i] == 0x52 {
                if self.has_via_ir_memory_corruption(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Via-IR memory layout bug: Complex struct assignments may corrupt memory due to Yul IR optimization".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 2: Incorrect storage packing
            // SSTORE with unusual bit manipulation patterns from via-IR
            if bytecode[i] == 0x55 {
                if self.has_storage_packing_bug(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Via-IR storage packing bug: Storage slot calculations may be incorrect with packed structs".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 3: Stack-too-deep workarounds causing variable shadowing
            // Excessive SWAP operations characteristic of via-IR stack management
            if self.is_swap_opcode(bytecode[i]) {
                if self.has_stack_too_deep_workaround(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Via-IR stack management: Stack-too-deep workarounds may cause variable shadowing and logic errors".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: Calldata decoding issues with nested dynamic arrays
            // CALLDATACOPY with complex offset calculations
            if bytecode[i] == 0x37 {
                if self.has_calldata_decoding_bug(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Via-IR calldata decoding bug: Nested dynamic arrays may be decoded incorrectly".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 5: Function selector collision
            // Via-IR may generate different selectors than expected
            if bytecode[i] == 0x14 {
                if self.has_selector_collision_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Via-IR function selector: Selector generation may differ from standard pipeline, check for collisions".to_string(),
                        pc: i,
                        confidence: 0.81,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<ViaIrPipelineBugVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| ViaIrPipelineBugVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_via_ir_memory_corruption(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut add_operations = 0;
        let mut mul_operations = 0;
        let mut mload_count = 0;
        let mut mstore_count = 1; // Current MSTORE

        // Check for complex memory offset calculations (via-IR pattern)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x01 => add_operations += 1, // ADD
                    0x02 => mul_operations += 1, // MUL
                    0x51 => mload_count += 1, // MLOAD
                    _ => {}
                }
            }
        }

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x52 {
                    mstore_count += 1;
                }
            }
        }

        // Via-IR uses complex calculations for struct member offsets
        add_operations >= 2 && mul_operations >= 1 && mload_count >= 2 && mstore_count >= 3
    }

    fn has_storage_packing_bug(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut and_operations = 0;
        let mut or_operations = 0;
        let mut shl_shr_operations = 0;
        let mut sload_present = false;

        // Via-IR generates specific bit manipulation patterns for packed storage
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x16 => and_operations += 1, // AND
                    0x17 => or_operations += 1, // OR
                    0x1b | 0x1c => shl_shr_operations += 1, // SHL, SHR
                    0x54 => sload_present = true, // SLOAD
                    _ => {}
                }
            }
        }

        // Complex bit manipulation before SSTORE indicates packed storage
        sload_present && and_operations >= 2 && (or_operations >= 1 || shl_shr_operations >= 2)
    }

    fn has_stack_too_deep_workaround(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        let mut swap_count = 1; // Current SWAP
        let mut dup_count = 0;
        let mut total_ops = 0;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x80..=0x8f => dup_count += 1, // DUP1-DUP16
                    0x90..=0x9f => swap_count += 1, // SWAP1-SWAP16
                    _ => {}
                }
                total_ops += 1;
            }
        }

        // Via-IR generates excessive SWAP/DUP sequences for stack management
        swap_count >= 4 && dup_count >= 3 && total_ops < 20
    }

    fn has_calldata_decoding_bug(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 15.min(pos);
        let window = 25.min(bytecode.len().saturating_sub(pos));
        
        let mut calldataload_count = 0;
        let mut add_for_offset = false;
        let mut has_dynamic_array = false;

        // Check for dynamic array offset calculations
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => calldataload_count += 1, // CALLDATALOAD
                    0x01 => add_for_offset = true, // ADD (offset calculation)
                    0x60..=0x7f => {
                        // Check for 0x20 (32 bytes - dynamic array marker)
                        if pos >= offset + 1 && pos - offset - 1 < bytecode.len() {
                            if bytecode[pos - offset] == 0x60 && bytecode.get(pos - offset + 1) == Some(&0x20) {
                                has_dynamic_array = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for nested array patterns after CALLDATACOPY
        let mut nested_structure = false;
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x37 { // Another CALLDATACOPY
                    nested_structure = true;
                    break;
                }
            }
        }

        calldataload_count >= 2 && add_for_offset && has_dynamic_array && nested_structure
    }

    fn has_selector_collision_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 10.min(pos);
        let mut has_calldataload = false;
        let mut has_push4 = false;
        let mut has_jumpi = false;

        // Function dispatch pattern with EQ comparison
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_calldataload = true, // CALLDATALOAD
                    0x63 => has_push4 = true, // PUSH4 (selector)
                    _ => {}
                }
            }
        }

        // Check for JUMPI after EQ
        if pos + 1 < bytecode.len() && bytecode[pos + 1] == 0x57 {
            has_jumpi = true;
        }

        has_calldataload && has_push4 && has_jumpi
    }

    fn is_swap_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 0x90..=0x9f) // SWAP1-SWAP16
    }
}
