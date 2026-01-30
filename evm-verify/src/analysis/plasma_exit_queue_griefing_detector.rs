use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PlasmaExitQueueGriefingDetector;

impl PlasmaExitQueueGriefingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_exit_queue(bytecode, i) && self.lacks_griefing_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Plasma exit queue griefing: exit queue without griefing protection allows denial of service".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_exit_queue(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;
        let mut has_add = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    0x01 => has_add = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore && has_add
    }

    fn lacks_griefing_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut limit_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x10 | 0x12 => limit_checks += 1,
                    _ => {}
                }
            }
        }

        limit_checks < 2
    }
}
