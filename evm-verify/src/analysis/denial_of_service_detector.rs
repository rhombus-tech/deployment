/// Denial Of Service Detector
use crate::bytecode::SecurityFinding;

pub struct DenialOfServiceDetector {
    bytecode: Vec<u8>,
}

impl DenialOfServiceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Denial of service vulnerability at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_dos_pattern(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_dos_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Pattern 1: Unbounded loops with external calls
        if self.bytecode[pos] == 0x57 { // JUMPI (loop)
            if pos + 30 < self.bytecode.len() {
                for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0xf1 | 0xfa) { // CALL, STATICCALL
                        // Check if loop bound depends on external state
                        if self.has_external_dependency(pos) {
                            return true;
                        }
                    }
                }
            }
        }
        
        // Pattern 2: Block gas limit issues
        if self.bytecode[pos] == 0x45 { // GASLIMIT
            if pos + 15 < self.bytecode.len() {
                // Check if used in loop or array operations
                for j in (pos + 1)..(pos + 15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 { // JUMPI
                        return true;
                    }
                }
            }
        }
        
        // Pattern 3: Unbounded array iteration
        if self.bytecode[pos] == 0x51 { // MLOAD (array access)
            if pos > 20 && pos + 20 < self.bytecode.len() {
                let mut has_loop = false;
                let mut has_bound_check = false;
                
                for j in pos.saturating_sub(20)..(pos + 20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 {
                        has_loop = true;
                    }
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT
                        has_bound_check = true;
                    }
                }
                
                return has_loop && !has_bound_check;
            }
        }
        
        false
    }

    fn has_external_dependency(&self, pos: usize) -> bool {
        if pos < 30 { return false; }
        
        for i in pos.saturating_sub(30)..pos {
            if i >= self.bytecode.len() { break; }
            // Check for SLOAD (external state read)
            if self.bytecode[i] == 0x54 {
                return true;
            }
            // Check for CALLDATALOAD (user input)
            if self.bytecode[i] == 0x35 {
                return true;
            }
        }
        false
    }
}
