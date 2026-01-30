use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct AugurReporterCoordinationAttackDetector;

impl AugurReporterCoordinationAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_reporter_mechanism(bytecode, i) && self.lacks_stake_requirement(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Augur reporter coordination attack: reporter mechanism without stake requirement allows coordination attacks".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_reporter_mechanism(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore
    }

    fn lacks_stake_requirement(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut balance_check = false;
        let mut comparison = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x31 => balance_check = true,
                    0x10 | 0x12 => comparison = true,
                    _ => {}
                }
            }
        }

        !balance_check || !comparison
    }
}
