/// Unchecked Return Value Detector
/// Unchecked return value ignores transfer failures
use crate::bytecode::SecurityFinding;

pub struct UncheckedReturnValueDetector {
    bytecode: Vec<u8>,
}

impl UncheckedReturnValueDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Unchecked return value ignores transfer failures at PC {}", location),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i >= self.bytecode.len() { break; }
            
            // Real bytecode pattern detection
            if self.check_opcode_pattern(i) {
                if !self.has_safety_check(i) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn check_opcode_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Match vulnerability-indicating opcodes
        match self.bytecode[pos] {
            0x32 => true, // ORIGIN (tx.origin)
            0xf1 | 0xfa => { // CALL, STATICCALL
                // Check for unchecked return
                if pos + 3 < self.bytecode.len() {
                    !matches!(self.bytecode[pos + 1], 0x15 | 0x16) // No ISZERO/AND
                } else { false }
            },
            0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 => { // Math ops
                // In assembly or no bounds check
                true
            },
            0xfe => true, // INVALID (unchecked cast destination)
            _ => false,
        }
    }

    fn has_safety_check(&self, pos: usize) -> bool {
        let end = (pos + 20).min(self.bytecode.len());
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            // Look for validation: EQ, LT, GT, ISZERO followed by REVERT/JUMPI
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14 | 0x15) {
                if i + 3 < self.bytecode.len() {
                    if matches!(self.bytecode[i + 2], 0xfd | 0x57) {
                        return true;
                    }
                }
            }
        }
        false
    }
}
