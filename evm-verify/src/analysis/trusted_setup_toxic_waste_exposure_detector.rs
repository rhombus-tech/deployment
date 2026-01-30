use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct TrustedSetupToxicWasteExposureDetector;

impl TrustedSetupToxicWasteExposureDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_trusted_setup_logic(bytecode, i) && self.lacks_waste_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Trusted setup toxic waste exposure: trusted setup operations without waste protection allow ceremony compromise".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_trusted_setup_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_call = false;
        let mut has_keccak = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0xf1 | 0xfa | 0xf4 => has_call = true,
                    0x20 => has_keccak = true,
                    _ => {}
                }
            }
        }

        has_sload && has_call && has_keccak
    }

    fn lacks_waste_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut destruction_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xff | 0x55 => destruction_checks += 1,
                    _ => {}
                }
            }
        }

        destruction_checks < 2
    }
}
