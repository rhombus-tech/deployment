use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FlashbotsBundleManipulationDetector;

impl FlashbotsBundleManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_bundle_logic(bytecode, i) && self.lacks_bundle_validation(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Flashbots bundle manipulation: bundle logic without validation allows manipulation".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_bundle_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => has_call = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_call && has_sstore
    }

    fn lacks_bundle_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut validation_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x33 | 0x32 => validation_checks += 1,
                    _ => {}
                }
            }
        }

        validation_checks < 2
    }
}
