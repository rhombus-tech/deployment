use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct SovereignRollupDaWithholdingDetector;

impl SovereignRollupDaWithholdingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_data_availability_logic(bytecode, i) && self.lacks_withholding_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Sovereign rollup DA withholding: data availability logic without withholding protection allows censorship".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_data_availability_logic(&self, bytecode: &[u8], pos: usize) -> bool {
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

    fn lacks_withholding_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut verification_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 | 0x14 => verification_checks += 1,
                    _ => {}
                }
            }
        }

        verification_checks < 3
    }
}
