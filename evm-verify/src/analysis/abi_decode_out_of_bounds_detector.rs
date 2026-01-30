use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// ABI Decode Out of Bounds Detector
///
/// Detects vulnerabilities where ABI decoding operations can read beyond calldata bounds,
/// leading to undefined behavior, incorrect data interpretation, or security exploits.
///
/// Vulnerability Scenarios:
/// - Reading beyond CALLDATASIZE without bounds check
/// - Incorrect offset calculations in dynamic array decoding
/// - Missing validation for dynamic types (bytes, string)
/// - Unchecked pointer arithmetic in ABI decoding
/// - Struct decoding without size validation
///
/// Real-World Cases:
/// - Multiple contracts exploited via malformed calldata
/// - ABI decoding bugs in proxy contracts
/// - Malicious calldata causing fund loss
/// - External call data manipulation
///
/// Detection Strategy:
/// - Identifies CALLDATALOAD without CALLDATASIZE check
/// - Detects unsafe offset calculations
/// - Looks for missing bounds validation
/// - Checks for dynamic type handling issues
/// - Identifies unchecked array/struct decoding
pub struct AbiDecodeOutOfBoundsDetector;

impl AbiDecodeOutOfBoundsDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: CALLDATALOAD without size check
            if bytecode[i] == 0x35 {
                if self.has_unchecked_calldataload(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unchecked CALLDATALOAD: Reading calldata without CALLDATASIZE validation enables out-of-bounds access".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: Dynamic array decoding without bounds check
            if bytecode[i] == 0x35 {
                if self.has_unsafe_dynamic_array_decode(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unsafe dynamic array decode: Array length not validated, enables out-of-bounds calldata access".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 3: CALLDATACOPY with unchecked size
            if bytecode[i] == 0x37 {
                if self.has_unchecked_calldatacopy(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unchecked CALLDATACOPY: Copying calldata without size validation can read beyond bounds".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 4: Offset arithmetic without overflow check
            if bytecode[i] == 0x01 {
                if self.has_unsafe_offset_arithmetic(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unsafe offset arithmetic: ABI offset calculation without overflow check enables out-of-bounds access".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 5: Struct decoding without validation
            if bytecode[i] == 0x35 {
                if self.has_unsafe_struct_decode(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Unsafe struct decode: Struct field access without bounds validation can read invalid memory".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_unchecked_calldataload(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let window = 15.min(bytecode.len().saturating_sub(pos));
        
        let mut has_calldatasize_check = false;
        let mut has_comparison = false;
        let mut has_revert = false;

        // Check for CALLDATASIZE validation before load
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x36 => has_calldatasize_check = true, // CALLDATASIZE
                    0x10 | 0x11 => has_comparison = true, // LT, GT (bounds check)
                    _ => {}
                }
            }
        }

        // Check for revert on invalid size
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xfd {
                    has_revert = true;
                    break;
                }
            }
        }

        // CALLDATALOAD without proper bounds checking
        !(has_calldatasize_check && has_comparison && has_revert)
    }

    fn has_unsafe_dynamic_array_decode(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let window = 40.min(bytecode.len().saturating_sub(pos));
        
        let mut has_length_load = false;
        let mut has_bounds_check = false;
        let mut has_loop = false;
        let mut has_mul_for_offset = false;

        // Check for array length loading
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x35 {
                    has_length_load = true; // Previous CALLDATALOAD (length)
                }
            }
        }

        // Check for bounds validation and offset calculation
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x11 => has_bounds_check = true, // LT, GT
                    0x02 => has_mul_for_offset = true, // MUL (offset calculation)
                    0x57 => has_loop = true, // JUMPI (array iteration)
                    _ => {}
                }
            }
        }

        // Dynamic array access without proper bounds checking
        has_length_load && has_mul_for_offset && !has_bounds_check && has_loop
    }

    fn has_unchecked_calldatacopy(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut has_calldatasize_check = false;
        let mut has_size_validation = false;
        let mut has_hardcoded_size = false;

        // Check for size validation before copy
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x36 => has_calldatasize_check = true, // CALLDATASIZE
                    0x10 | 0x11 | 0x14 => has_size_validation = true, // LT, GT, EQ
                    0x60..=0x7f => has_hardcoded_size = true, // PUSH (size param)
                    _ => {}
                }
            }
        }

        // CALLDATACOPY with size but no validation
        has_hardcoded_size && !(has_calldatasize_check && has_size_validation)
    }

    fn has_unsafe_offset_arithmetic(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let window = 25.min(bytecode.len().saturating_sub(pos));
        
        let mut has_calldataload_before = false;
        let mut has_offset_base = false;
        let mut has_overflow_check = false;
        let mut has_calldataload_after = false;

        // Check for offset calculation pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_calldataload_before = true, // CALLDATALOAD
                    0x60..=0x7f => has_offset_base = true, // PUSH (base offset)
                    0x10 | 0x11 => has_overflow_check = true, // LT, GT (overflow check)
                    _ => {}
                }
            }
        }

        // Check for CALLDATALOAD using calculated offset
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x35 {
                    has_calldataload_after = true;
                    break;
                }
            }
        }

        // Offset arithmetic for ABI decoding without overflow protection
        has_calldataload_before && has_offset_base && has_calldataload_after && !has_overflow_check
    }

    fn has_unsafe_struct_decode(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut calldataload_count = 1; // Current CALLDATALOAD
        let mut has_struct_pattern = false;
        let mut has_bounds_check = false;
        let mut offset_operations = 0;

        // Count multiple CALLDATALOAD operations (struct fields)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => calldataload_count += 1,
                    0x01 => offset_operations += 1, // ADD (offset increment)
                    0x36 => has_bounds_check = true, // CALLDATASIZE check
                    _ => {}
                }
            }
        }

        // Check for additional field loads
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x35 => calldataload_count += 1,
                    0x01 => offset_operations += 1,
                    _ => {}
                }
            }
        }

        // Struct pattern: multiple loads with offset increments
        if calldataload_count >= 3 && offset_operations >= 2 {
            has_struct_pattern = true;
        }

        // Struct decoding without size validation
        has_struct_pattern && !has_bounds_check
    }
}
