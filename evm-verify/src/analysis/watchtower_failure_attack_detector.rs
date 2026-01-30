use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct WatchtowerFailureAttackDetector;

impl WatchtowerFailureAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_watchtower_logic(bytecode, i) && self.lacks_failure_handling(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Watchtower failure attack: watchtower logic without failure handling allows channel theft".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_watchtower_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;
        let mut has_call = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x14 => has_comparison = true,
                    0xf1 | 0xfa => has_call = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison && has_call
    }

    fn lacks_failure_handling(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut fallback_checks = 0;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x57 => fallback_checks += 1,
                    _ => {}
                }
            }
        }

        fallback_checks < 2
    }
}
