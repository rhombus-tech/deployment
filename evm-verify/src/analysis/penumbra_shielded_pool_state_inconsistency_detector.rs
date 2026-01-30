use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PenumbraShieldedPoolStateInconsistencyDetector;

impl PenumbraShieldedPoolStateInconsistencyDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_shielded_pool_state(bytecode, i) && self.lacks_consistency_check(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Penumbra shielded pool state inconsistency: shielded pool state updates without consistency checks allow double-spending".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_shielded_pool_state(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;
        let mut has_arithmetic = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    0x01 | 0x03 => has_arithmetic = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore && has_arithmetic
    }

    fn lacks_consistency_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut validation_checks = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 | 0x12 => validation_checks += 1,
                    _ => {}
                }
            }
        }

        validation_checks < 3
    }
}
