/// Array Bounds Overflow Detector
use crate::bytecode::SecurityFinding;

pub struct ArrayBoundsOverflowDetector {
    bytecode: Vec<u8>,
}

impl ArrayBoundsOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Array bounds overflow vulnerability at PC {}", location),
                pc: location,
                confidence: 0.93,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_array_access(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_array_access(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for MLOAD/MSTORE with calculated index without bounds check
        if matches!(self.bytecode[pos], 0x51 | 0x52) { // MLOAD, MSTORE
            if pos > 15 {
                // Look for index calculation (MUL or ADD for array indexing)
                let mut has_index_calc = false;
                let mut has_bounds_check = false;
                
                for j in pos.saturating_sub(15)..pos {
                    if matches!(self.bytecode[j], 0x01 | 0x02) { // ADD, MUL
                        has_index_calc = true;
                    }
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT
                        if j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0xfd | 0x57) {
                                has_bounds_check = true;
                            }
                        }
                    }
                }
                
                return has_index_calc && !has_bounds_check;
            }
        }
        
        // Check for CALLDATACOPY with unchecked length
        if self.bytecode[pos] == 0x37 { // CALLDATACOPY
            if pos > 10 {
                let mut has_length_check = false;
                for j in pos.saturating_sub(10)..pos {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) {
                        has_length_check = true;
                        break;
                    }
                }
                return !has_length_check;
            }
        }
        
        false
    }
}
