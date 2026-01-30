use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct LightningNetworkStyleGriefingDetector;

impl LightningNetworkStyleGriefingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_channel_logic(bytecode, i) && self.lacks_griefing_protection(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Lightning Network style griefing: channel logic without griefing protection allows timelock exploitation".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_channel_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_call = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => has_comparison = true,
                    0xf1 | 0xfa => has_call = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_call
    }

    fn lacks_griefing_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut penalty_checks = 0;

        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x54 && bytecode[pos + offset + 1] == 0x10 {
                    penalty_checks += 1;
                }
            }
        }

        penalty_checks < 1
    }
}
