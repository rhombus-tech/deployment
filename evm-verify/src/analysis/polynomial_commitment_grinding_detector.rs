use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PolynomialCommitmentGrindingDetector;

impl PolynomialCommitmentGrindingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_polynomial_commitment(bytecode, i) && self.lacks_grinding_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Polynomial commitment grinding: polynomial commitment without grinding protection allows proof manipulation".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_polynomial_commitment(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_keccak = false;
        let mut has_call = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => has_keccak = true,
                    0xf1 | 0xfa => has_call = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_keccak && has_call && has_sstore
    }

    fn lacks_grinding_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut randomness_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x40 || bytecode[pos - offset] == 0x42 {
                    randomness_checks += 1;
                }
            }
        }

        randomness_checks < 1
    }
}
