use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct RetroactivePublicGoodsFundingGamingDetector;

impl RetroactivePublicGoodsFundingGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_retroactive_funding(bytecode, i) && self.lacks_gaming_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Medium,
                    description: "Retroactive public goods funding gaming: retroactive funding without gaming protection allows reward exploitation".to_string(),
                    pc: i,
                    confidence: 0.83,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_retroactive_funding(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_call = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0xf1 | 0xfa => has_call = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_call && has_sstore
    }

    fn lacks_gaming_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut validation_count = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x10 | 0x14 => validation_count += 1,
                    _ => {}
                }
            }
        }

        validation_count < 2
    }
}
