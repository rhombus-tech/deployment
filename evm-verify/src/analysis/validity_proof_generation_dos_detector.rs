use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct ValidityProofGenerationDosDetector;

impl ValidityProofGenerationDosDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_proof_generation(bytecode, i) && self.lacks_dos_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Validity proof generation DOS: proof generation without DOS protection allows resource exhaustion".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_proof_generation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_loop = false;
        let mut has_call = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x57 => has_loop = true,
                    0xf1 | 0xfa | 0xf4 => has_call = true,
                    _ => {}
                }
            }
        }

        has_loop && has_call
    }

    fn lacks_dos_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut gas_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x5a | 0x45 => gas_checks += 1,
                    _ => {}
                }
            }
        }

        gas_checks < 1
    }
}
