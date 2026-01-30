/// Off-By-One Error Detector
/// Detects off-by-one errors in loops and array access patterns
/// Vulnerable pattern: Using <= instead of < in loop conditions, or wrong array bounds

use crate::bytecode::SecurityFinding;

pub struct OffByOneErrorDetector {
    bytecode: Vec<u8>,
}

impl OffByOneErrorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Check for off-by-one in loops
        if let Some(location) = self.has_loop_off_by_one() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Off-by-one error at PC {}. Loop condition uses <= instead of < allowing out-of-bounds access",
                    location
                ),
                pc: location,
                confidence: 0.85,
            });
        }

        // Check for array access off-by-one
        if let Some(location) = self.has_array_access_off_by_one() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Array access off-by-one at PC {}. Index calculation allows access beyond array bounds",
                    location
                ),
                pc: location,
                confidence: 0.88,
            });
        }

        findings
    }

    fn has_loop_off_by_one(&self) -> Option<usize> {
        // Pattern: counter comparison (LT/GT) with array length, followed by JUMPI
        // Vulnerable when using EQ or not checking bounds properly
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x14 { // EQ (wrong - should be LT/GT)
                // Check if this is in a loop context (preceded by counter and length)
                if i > 10 && self.has_loop_structure_around(i) {
                    // Followed by JUMPI indicates conditional loop
                    for j in (i + 1)..(i + 10).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x57 { // JUMPI
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_loop_structure_around(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(30);
        
        // Look for: DUP (counter), SLOAD/CALLDATALOAD (length), comparison
        let mut has_counter = false;
        let mut has_length = false;
        
        for i in start..pos {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] >= 0x80 && self.bytecode[i] <= 0x8f { // DUP1-DUP16
                has_counter = true;
            }
            if self.bytecode[i] == 0x54 || self.bytecode[i] == 0x35 { // SLOAD or CALLDATALOAD
                has_length = true;
            }
        }
        
        has_counter && has_length
    }

    fn has_array_access_off_by_one(&self) -> Option<usize> {
        // Pattern: index + 1, followed by array access without bounds check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x01 { // ADD (index + 1)
                // Check if followed by array access (MLOAD/SLOAD)
                for j in (i + 1)..(i + 20).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x51 || self.bytecode[j] == 0x54 { // MLOAD or SLOAD
                        // Check if there's NO bounds check before access
                        if !self.has_bounds_check_between(i, j) {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_bounds_check_between(&self, start: usize, end: usize) -> bool {
        for i in start..end {
            if i >= self.bytecode.len() { break; }
            // Look for LT (0x10) or GT (0x11) indicating bounds check
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                // Should be followed by ISZERO + conditional REVERT
                if i + 5 < self.bytecode.len() {
                    if self.bytecode[i + 1] == 0x15 && self.bytecode[i + 3] == 0xfd {
                        return true;
                    }
                }
            }
        }
        false
    }
}
