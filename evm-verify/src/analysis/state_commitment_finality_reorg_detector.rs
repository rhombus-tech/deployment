use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct StateCommitmentFinalityReorgDetector;

impl StateCommitmentFinalityReorgDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_state_commitment(bytecode, i) && self.lacks_finality_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "State commitment finality reorg: state commitment without finality protection allows reorg attacks".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_state_commitment(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_keccak = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => has_keccak = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_keccak && has_sstore
    }

    fn lacks_finality_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut finality_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x43 || bytecode[pos - offset] == 0x42 {
                    finality_checks += 1;
                }
            }
        }

        finality_checks < 1
    }
}
