use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct RailgunPrivateBalanceDeanonymizationDetector;

impl RailgunPrivateBalanceDeanonymizationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_private_balance_logic(bytecode, i) && self.lacks_deanonymization_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Railgun private balance deanonymization: private balance operations without protection allow balance tracking".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_private_balance_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_add_or_sub = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x01 | 0x03 => has_add_or_sub = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_add_or_sub && has_sstore
    }

    fn lacks_deanonymization_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut hash_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x20 {
                hash_count += 1;
            }
        }

        hash_count < 2
    }
}
