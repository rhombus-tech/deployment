/// Allowance Check Insufficient Detector
/// Detects transferFrom without proper allowance validation
use crate::bytecode::SecurityFinding;

pub struct AllowanceCheckInsufficientDetector {
    bytecode: Vec<u8>,
}

impl AllowanceCheckInsufficientDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.has_insufficient_allowance_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Insufficient allowance check at PC {}. transferFrom executes without verifying approved amount",
                    location
                ),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn has_insufficient_allowance_check(&self) -> Option<usize> {
        // transferFrom selector: 0x23b872dd
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i + 4 >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x63 {
                let sel = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                if sel == 0x23b872dd {
                    if !self.has_proper_allowance_check_after(i) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_proper_allowance_check_after(&self, pos: usize) -> bool {
        let end = (pos + 150).min(self.bytecode.len());
        let mut found_allowance_load = false;
        let mut found_comparison = false;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x54 { found_allowance_load = true; }
            if found_allowance_load && (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) {
                found_comparison = true;
            }
            if found_comparison && (self.bytecode[i] == 0xfd || self.bytecode[i] == 0x57) {
                return true;
            }
        }
        false
    }
}
