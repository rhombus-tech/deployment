use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct RageQuitMechanismAbuseDetector;

impl RageQuitMechanismAbuseDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_rage_quit_logic(bytecode, i) && self.lacks_abuse_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Rage quit mechanism abuse: rage quit logic without abuse protection allows unfair advantage".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_rage_quit_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_transfer = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0xf1 | 0xfa => has_transfer = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_transfer && has_sstore
    }

    fn lacks_abuse_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x42 && bytecode[pos - offset + 1] == 0x10 {
                    return false;
                }
            }
        }
        true
    }
}
