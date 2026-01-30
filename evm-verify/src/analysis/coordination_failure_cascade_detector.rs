use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct CoordinationFailureCascadeDetector;

impl CoordinationFailureCascadeDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_multi_party_coordination(bytecode, i) && self.lacks_failure_recovery(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Coordination failure cascade vulnerability: multi-party coordination without failure recovery mechanism".to_string(),
                    pc: i,
                    confidence: 0.84,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_multi_party_coordination(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut sload_count = 0;
        let mut comparison_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => sload_count += 1,
                    0x10 | 0x12 | 0x14 => comparison_count += 1,
                    _ => {}
                }
            }
        }

        sload_count >= 3 && comparison_count >= 2
    }

    fn lacks_failure_recovery(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x57 && bytecode[pos + offset + 1] == 0x55 {
                    return false;
                }
            }
        }
        true
    }
}
