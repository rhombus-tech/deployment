/// Boundary Condition Detector
/// Boundary condition not properly checked
use crate::bytecode::SecurityFinding;

pub struct BoundaryConditionDetector {
    bytecode: Vec<u8>,
}

impl BoundaryConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Boundary condition not properly checked at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i >= self.bytecode.len() { break; }
            
            if self.matches_vulnerability_pattern(i) {
                if !self.has_mitigation(i) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn matches_vulnerability_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        match self.bytecode[pos] {
            0x04 => { // DIV
                // Check for rounding/precision loss
                if pos + 20 < self.bytecode.len() {
                    for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x02 { // MUL after DIV
                            return true;
                        }
                    }
                }
                false
            },
            0xfe => { // INVALID (type conversion issues)
                true
            },
            0x10 | 0x11 => { // LT, GT (boundary checks)
                // Check if boundary properly validated
                if pos + 10 < self.bytecode.len() {
                    !matches!(self.bytecode[pos + 3], 0x57 | 0xfd)
                } else {
                    false
                }
            },
            0x54 => { // SLOAD
                // Check for state consistency
                if pos + 30 < self.bytecode.len() {
                    let mut sload_count = 0;
                    for j in pos..(pos + 30).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x54 {
                            sload_count += 1;
                        }
                    }
                    sload_count >= 2 // Multiple reads suggest state dependency
                } else {
                    false
                }
            },
            0x5a => { // GAS opcode
                // Gas manipulation
                if pos + 15 < self.bytecode.len() {
                    for j in (pos + 1)..(pos + 15).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if matches!(self.bytecode[j], 0xf1 | 0xf2) { // CALL/CALLCODE
                            return true;
                        }
                    }
                }
                false
            },
            0x42 => { // TIMESTAMP
                // Timestamp used in logic
                if pos + 20 < self.bytecode.len() {
                    for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if matches!(self.bytecode[j], 0x14 | 0x10 | 0x11) { // EQ/LT/GT
                            return true;
                        }
                    }
                }
                false
            },
            0xff => { // SELFDESTRUCT
                true
            },
            0x3b => { // EXTCODESIZE
                // Check for constructor bypass
                true
            },
            _ => false,
        }
    }

    fn has_mitigation(&self, pos: usize) -> bool {
        let check_start = pos.saturating_sub(20);
        let check_end = (pos + 30).min(self.bytecode.len());
        
        for i in check_start..check_end {
            if i >= self.bytecode.len() { break; }
            
            // Look for validation patterns
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14 | 0x15) {
                if i + 4 < self.bytecode.len() {
                    if matches!(self.bytecode[i + 2], 0xfd | 0x57) {
                        return true;
                    }
                }
            }
        }
        false
    }
}
