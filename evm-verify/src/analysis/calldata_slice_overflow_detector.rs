use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Calldata Slice Overflow Detector
///
/// Detects vulnerabilities where calldata slicing operations can overflow or access
/// out-of-bounds data, leading to incorrect decoding and security exploits.
///
/// Vulnerability Scenarios:
/// - Slice length exceeding available calldata
/// - Offset + length overflow causing wraparound
/// - Unchecked slice bounds in multi-call operations
/// - Dynamic slicing without validation
/// - Batch decoding with incorrect slice calculations
///
/// Real-World Cases:
/// - Router contracts with malformed multi-call data
/// - Proxy contracts with incorrect calldata forwarding
/// - Batch transaction processors with overflow bugs
/// - ABI proxy patterns with slice vulnerabilities
///
/// Detection Strategy:
/// - Identifies slice operations without bounds checks
/// - Detects offset + length calculations without overflow protection
/// - Looks for CALLDATACOPY with dynamic parameters
/// - Checks for slice operations in loops
/// - Identifies missing CALLDATASIZE validation
pub struct CalldataSliceOverflowDetector;

impl CalldataSliceOverflowDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: CALLDATACOPY with dynamic length
            if bytecode[i] == 0x37 {
                if self.has_dynamic_slice_without_bounds(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Calldata slice overflow: Dynamic CALLDATACOPY without bounds check enables out-of-bounds access".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 2: Offset + length addition without overflow check
            if bytecode[i] == 0x01 {
                if self.has_unsafe_offset_length_addition(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Slice offset overflow: Offset + length addition without overflow check can wrap around".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: Multi-call with slice extraction
            if bytecode[i] == 0x37 {
                if self.has_multicall_slice_vulnerability(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Multi-call slice vulnerability: Batch operations slice calldata without proper validation".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 4: Loop-based slicing without bounds
            if bytecode[i] == 0x37 {
                if self.has_loop_based_slicing(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Loop slice overflow: Iterative calldata slicing without cumulative bounds checking".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 5: CALLDATALOAD sequence without size check
            if bytecode[i] == 0x35 {
                if self.has_sequential_load_without_validation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Sequential calldata access: Multiple CALLDATALOAD operations without size validation".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_dynamic_slice_without_bounds(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_calldatasize = false;
        let mut has_dynamic_length = false;
        let mut has_bounds_check = false;
        let mut length_from_calldata = false;

        // Check slice parameters
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x36 => has_calldatasize = true, // CALLDATASIZE
                    0x35 => length_from_calldata = true, // CALLDATALOAD (dynamic length)
                    0x54 => has_dynamic_length = true, // SLOAD (length from storage)
                    0x10 | 0x11 => has_bounds_check = true, // LT, GT (validation)
                    _ => {}
                }
            }
        }

        // Dynamic slice without proper validation
        (length_from_calldata || has_dynamic_length) && !has_bounds_check && !has_calldatasize
    }

    fn has_unsafe_offset_length_addition(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let window = 20.min(bytecode.len().saturating_sub(pos));
        
        let mut has_offset = false;
        let mut has_length = false;
        let mut has_overflow_check = false;
        let mut has_calldatacopy = false;

        // ADD operation for offset + length
        // Check operands
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => {
                        // CALLDATALOAD could be offset or length
                        if has_offset {
                            has_length = true;
                        } else {
                            has_offset = true;
                        }
                    }
                    0x10 | 0x11 => has_overflow_check = true, // LT, GT
                    _ => {}
                }
            }
        }

        // Check if result used in CALLDATACOPY
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x37 => has_calldatacopy = true, // CALLDATACOPY
                    0x10 | 0x11 => has_overflow_check = true, // Post-addition check
                    _ => {}
                }
            }
        }

        // Offset + length for slicing without overflow check
        has_offset && has_length && has_calldatacopy && !has_overflow_check
    }

    fn has_multicall_slice_vulnerability(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_loop = false;
        let mut has_offset_increment = false;
        let mut has_size_check = false;
        let mut calldatacopy_count = 1; // Current CALLDATACOPY

        // Check for multi-call pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => has_loop = true, // JUMPI (loop)
                    0x01 => has_offset_increment = true, // ADD (offset update)
                    0x36 => has_size_check = true, // CALLDATASIZE
                    0x37 => calldatacopy_count += 1, // Multiple copies
                    _ => {}
                }
            }
        }

        // Multi-call slicing without validation
        (has_loop || calldatacopy_count >= 2) && has_offset_increment && !has_size_check
    }

    fn has_loop_based_slicing(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut in_loop = false;
        let mut has_cumulative_offset = false;
        let mut has_bounds_check = false;
        let mut has_counter = false;

        // Check for loop with cumulative offset
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => in_loop = true, // JUMPI
                    0x01 => {
                        // ADD for cumulative offset
                        if in_loop {
                            has_cumulative_offset = true;
                        }
                    }
                    0x03 => has_counter = true, // SUB (countdown)
                    0x10 | 0x11 => has_bounds_check = true, // LT, GT
                    _ => {}
                }
            }
        }

        // Loop slicing without proper bounds checking
        in_loop && has_cumulative_offset && has_counter && !has_bounds_check
    }

    fn has_sequential_load_without_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let lookback = 20.min(pos);
        
        let mut calldataload_count = 1; // Current CALLDATALOAD
        let mut has_calldatasize_check = false;
        let mut has_offset_increment = false;

        // Check for CALLDATASIZE validation
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x36 {
                    has_calldatasize_check = true;
                }
            }
        }

        // Count sequential CALLDATALOADs
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x35 => calldataload_count += 1,
                    0x01 => has_offset_increment = true, // ADD (moving to next field)
                    _ => {}
                }
            }
        }

        // Multiple sequential loads without validation
        calldataload_count >= 3 && has_offset_increment && !has_calldatasize_check
    }
}
