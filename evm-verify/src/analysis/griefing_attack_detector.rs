/// Griefing Attack Detector
use crate::bytecode::SecurityFinding;

pub struct GriefingAttackDetector {
    bytecode: Vec<u8>,
}

impl GriefingAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Griefing attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_griefing_pattern(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_griefing_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for external calls in loops that can be griefed
        if matches!(self.bytecode[pos], 0xf1 | 0xfa) { // CALL, STATICCALL
            // Look for JUMPI backwards (loop pattern)
            if pos > 30 {
                let mut in_loop = false;
                for j in pos.saturating_sub(30)..pos {
                    if self.bytecode[j] == 0x57 { // JUMPI
                        in_loop = true;
                        break;
                    }
                }
                
                if in_loop {
                    // Check if call failure is handled gracefully
                    if pos + 15 < self.bytecode.len() {
                        let mut has_failure_handling = false;
                        for k in (pos + 1)..(pos + 15).min(self.bytecode.len()) {
                            // Check for return value check
                            if matches!(self.bytecode[k], 0x15 | 0x16) { // ISZERO, AND
                                if k + 3 < self.bytecode.len() {
                                    // Check if it continues despite failure (not REVERT)
                                    if self.bytecode[k + 2] != 0xfd {
                                        has_failure_handling = true;
                                    }
                                }
                            }
                        }
                        // Vulnerable if it REVERTs on failure in loop
                        return !has_failure_handling;
                    }
                }
            }
        }
        
        // Check for unbounded gas consumption
        if self.bytecode[pos] == 0x5a { // GAS
            if pos + 20 < self.bytecode.len() {
                for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0xf1 | 0xfa) { // Forward all gas
                        return true;
                    }
                }
            }
        }
        
        false
    }
}
