use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FutarchyOracleGovernanceManipulationDetector;

impl FutarchyOracleGovernanceManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_futarchy_oracle(bytecode, i) && self.lacks_oracle_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Futarchy oracle governance manipulation: oracle-based governance without protection allows decision manipulation".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_futarchy_oracle(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_comparison = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa | 0xf4 => has_call = true,
                    0x10 | 0x14 => has_comparison = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_call && has_comparison && has_sstore
    }

    fn lacks_oracle_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut validation_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => validation_checks += 1,
                    _ => {}
                }
            }
        }

        validation_checks < 3
    }
}
