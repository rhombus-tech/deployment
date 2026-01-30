/// Balance Check Missing Detector
/// Detects transfers without checking sender balance first
use crate::bytecode::SecurityFinding;

pub struct BalanceCheckMissingDetector {
    bytecode: Vec<u8>,
}

impl BalanceCheckMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.has_unchecked_transfer() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Missing balance check at PC {}. Transfer executes without verifying sender has sufficient balance",
                    location
                ),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn has_unchecked_transfer(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i >= self.bytecode.len() { break; }
            // Transfer pattern: SUB (balance -= amount) followed by SSTORE
            if self.bytecode[i] == 0x03 && i + 10 < self.bytecode.len() { // SUB
                for j in (i+1)..(i+10).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x55 { // SSTORE (updating balance)
                        // Check if there was balance >= amount check before SUB
                        if !self.has_balance_check_before(i) {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_balance_check_before(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(50);
        for i in start..pos {
            if i >= self.bytecode.len() { break; }
            // Pattern: balance SLOAD, amount, LT/GT check
            if self.bytecode[i] == 0x54 && i + 8 < self.bytecode.len() { // SLOAD
                if self.bytecode[i+3] == 0x10 || self.bytecode[i+3] == 0x11 { // LT or GT
                    return true;
                }
            }
        }
        false
    }
}
