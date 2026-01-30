/// Return Value Unchecked Detector
use crate::bytecode::SecurityFinding;

pub struct ReturnValueUncheckedDetector {
    bytecode: Vec<u8>,
}

impl ReturnValueUncheckedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Unchecked external call return value at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.check_unchecked_call(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_unchecked_call(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for CALL, STATICCALL, DELEGATECALL without return value check
        if matches!(self.bytecode[pos], 0xf1 | 0xfa | 0xf4) {
            if pos + 10 < self.bytecode.len() {
                // Look for return value handling
                let mut checks_return = false;
                
                for j in (pos + 1)..(pos + 10).min(self.bytecode.len()) {
                    // ISZERO checks success, AND/OR for boolean logic
                    if matches!(self.bytecode[j], 0x15 | 0x16 | 0x17) { // ISZERO, AND, OR
                        checks_return = true;
                        break;
                    }
                    // Direct comparison
                    if self.bytecode[j] == 0x14 { // EQ
                        checks_return = true;
                        break;
                    }
                    // POP means they're ignoring it
                    if self.bytecode[j] == 0x50 { // POP
                        return true;
                    }
                }
                
                return !checks_return;
            }
        }
        false
    }
}
