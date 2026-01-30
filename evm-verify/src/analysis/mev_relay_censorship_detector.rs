use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct MevRelayCensorshipDetector;

impl MevRelayCensorshipDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_relay_logic(bytecode, i) && self.lacks_censorship_resistance(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "MEV relay censorship: relay logic without censorship resistance allows transaction filtering".to_string(),
                    pc: i,
                    confidence: 0.84,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_relay_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;
        let mut has_jumpi = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x14 => has_comparison = true,
                    0x57 => has_jumpi = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison && has_jumpi
    }

    fn lacks_censorship_resistance(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut call_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => call_count += 1,
                    _ => {}
                }
            }
        }

        call_count < 2
    }
}
