use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FraudProofChallengePeriodGamingDetector;

impl FraudProofChallengePeriodGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_challenge_period(bytecode, i) && self.lacks_gaming_protection(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Fraud proof challenge period gaming: timestamp-based challenge period without gaming protection allows manipulation".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_challenge_period(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_sstore = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => has_comparison = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_sstore
    }

    fn lacks_gaming_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut protection_checks = 0;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x57 => protection_checks += 1,
                    _ => {}
                }
            }
        }

        protection_checks < 2
    }
}
