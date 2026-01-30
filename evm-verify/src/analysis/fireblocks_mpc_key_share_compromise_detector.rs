use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FireblocksMpcKeyShareCompromiseDetector;

impl FireblocksMpcKeyShareCompromiseDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_mpc_key_logic(bytecode, i) && self.lacks_key_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Fireblocks MPC key share compromise: MPC key operations without proper protection allow key extraction".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_mpc_key_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_keccak = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x20 => has_keccak = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_keccak && has_sstore
    }

    fn lacks_key_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut protection_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x10 | 0x14 | 0x33 => protection_checks += 1,
                    _ => {}
                }
            }
        }

        protection_checks < 3
    }
}
