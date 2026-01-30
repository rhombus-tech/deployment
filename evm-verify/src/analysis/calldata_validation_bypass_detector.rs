/// Calldata Validation Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct CalldataValidationBypassDetector {
    bytecode: Vec<u8>,
}

impl CalldataValidationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Calldata validation bypass vulnerability at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_calldata_usage(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_calldata_usage(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for CALLDATALOAD without validation before use
        if self.bytecode[pos] == 0x35 { // CALLDATALOAD
            if pos + 30 < self.bytecode.len() {
                let mut has_validation = false;
                let mut is_used = false;
                
                for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                    // Check for validation (EQ, LT, GT checks with REVERT/JUMPI)
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) {
                        if j + 4 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0xfd | 0x57) {
                                has_validation = true;
                            }
                        }
                    }
                    
                    // Check if data is used in critical operations
                    if matches!(self.bytecode[j], 0x55 | 0xf1 | 0xf4) { // SSTORE, CALL, DELEGATECALL
                        is_used = true;
                    }
                }
                
                return is_used && !has_validation;
            }
        }
        false
    }
}
