use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PolkadotParachainFinalityDelayDetector;

impl PolkadotParachainFinalityDelayDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_finality_logic(bytecode, i) && self.lacks_delay_handling(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Polkadot parachain finality delay: finality checks without delay handling allow premature state transitions".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_finality_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x14 => has_comparison = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison
    }

    fn lacks_delay_handling(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut buffer_checks = 0;

        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x03 && bytecode[pos + offset + 1] == 0x10 {
                    buffer_checks += 1;
                }
            }
        }

        buffer_checks < 1
    }
}
