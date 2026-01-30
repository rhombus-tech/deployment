use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct NexusMutualClaimOracleManipulationDetector;

impl NexusMutualClaimOracleManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_claim_assessment(bytecode, i) && self.has_oracle_call(bytecode, i) && self.lacks_oracle_validation(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Nexus Mutual claim oracle manipulation: claim assessment relies on oracle without proper validation or multi-source verification".to_string(),
                    pc: i,
                    confidence: 0.91,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_claim_assessment(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x12 | 0x14 => has_comparison = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison
    }

    fn has_oracle_call(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0xf1 || op == 0xfa {
                    return true;
                }
            }
        }
        false
    }

    fn lacks_oracle_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut call_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0xf1 || op == 0xfa {
                    call_count += 1;
                }
            }
        }

        call_count < 2
    }
}
