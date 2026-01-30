use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct TransientStorageReentrancyBypassDetector;

impl TransientStorageReentrancyBypassDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x5c || bytecode[i] == 0x5d {
                if self.has_reentrancy_pattern(bytecode, i) && self.lacks_guard_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Transient storage reentrancy bypass: TLOAD/TSTORE without reentrancy guard allows state manipulation".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_reentrancy_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_storage_op = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa | 0xf4 => has_call = true,
                    0x5c | 0x5d | 0x54 | 0x55 => has_storage_op = true,
                    _ => {}
                }
            }
        }

        has_call && has_storage_op
    }

    fn lacks_guard_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut guard_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 | 0x14 | 0x57 => guard_checks += 1,
                    _ => {}
                }
            }
        }

        guard_checks < 2
    }
}
