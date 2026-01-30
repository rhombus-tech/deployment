use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct DeadlineParameterManipulationDetector;

impl DeadlineParameterManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_deadline_check(bytecode, i) && self.has_user_controlled_deadline(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Deadline parameter manipulation vulnerability: user-controlled deadline with timestamp comparison allows manipulation".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_deadline_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 10.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0x10 || op == 0x12 {
                    return true;
                }
            }
        }
        false
    }

    fn has_user_controlled_deadline(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 15.min(pos);
        for offset in 1..=lookback {
            if bytecode[pos - offset] == 0x35 {
                return true;
            }
        }
        false
    }
}
