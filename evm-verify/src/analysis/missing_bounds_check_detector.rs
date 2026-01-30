/// Missing Bounds Check Detector
/// Detects array/memory access without proper bounds validation
use crate::bytecode::SecurityFinding;

pub struct MissingBoundsCheckDetector {
    bytecode: Vec<u8>,
}

impl MissingBoundsCheckDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.has_unchecked_access() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Missing bounds check at PC {}. Array/memory access without validation allows out-of-bounds read/write",
                    location
                ),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn has_unchecked_access(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x51 || self.bytecode[i] == 0x52 { // MLOAD or MSTORE
                if !self.has_bounds_check_before(i) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_bounds_check_before(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(50);
        for i in start..pos {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x10 && i + 3 < self.bytecode.len() {
                if self.bytecode[i + 1] == 0x15 && self.bytecode[i + 2] == 0x60 { return true; }
            }
        }
        false
    }
}
