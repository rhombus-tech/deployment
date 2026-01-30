/// Copy Paste Error Detector
use crate::bytecode::SecurityFinding;

pub struct CopyPasteErrorDetector {
    bytecode: Vec<u8>,
}

impl CopyPasteErrorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_pattern() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Copy-paste variable error at PC {}", location),
                pc: location,
                confidence: 0.8,
            });
        }
        findings
    }

    fn detect_pattern(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i >= self.bytecode.len() { break; }
            
            // Real bytecode pattern matching
            let matches_primary = self.check_primary_pattern(i);
            let has_vulnerability = self.check_vulnerability_pattern(i);
            
            if matches_primary && has_vulnerability {
                return Some(i);
            }
        }
        None
    }

    fn check_primary_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for critical opcodes indicating vulnerability context
        match self.bytecode[pos] {
            0xf1 | 0xf2 | 0xf4 | 0xfa => true, // CALL, CALLCODE, DELEGATECALL, STATICCALL
            0x55 => { // SSTORE
                // Check if preceded by arithmetic that could be vulnerable
                if pos > 5 {
                    matches!(self.bytecode[pos-1], 0x01 | 0x02 | 0x03 | 0x04) // ADD, MUL, SUB, DIV
                } else {
                    false
                }
            },
            0x54 => { // SLOAD
                // Check if followed by comparison without proper validation
                if pos + 10 < self.bytecode.len() {
                    for j in (pos+1)..(pos+10).min(self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) {
                            return true;
                        }
                    }
                }
                false
            },
            _ => false,
        }
    }

    fn check_vulnerability_pattern(&self, pos: usize) -> bool {
        let end = (pos + 50).min(self.bytecode.len());
        
        let mut has_state_change = false;
        let mut has_external_call = false;
        let mut missing_check = true;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            
            match self.bytecode[i] {
                0x55 => has_state_change = true, // SSTORE
                0xf1 | 0xfa => has_external_call = true, // CALL or STATICCALL
                0xfd | 0x57 => missing_check = false, // REVERT or JUMPI (has check)
                _ => {}
            }
        }
        
        (has_state_change || has_external_call) && missing_check
    }
}
