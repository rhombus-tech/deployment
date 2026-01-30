use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PerpetualNftPositionLiquidationCascadeDetector;

impl PerpetualNftPositionLiquidationCascadeDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_position_liquidation(bytecode, i) && self.lacks_cascade_prevention(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Perpetual NFT position liquidation cascade: position liquidation without cascade prevention allows systemic risk".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_position_liquidation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_sstore = false;
        let mut has_call = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => has_comparison = true,
                    0x55 => has_sstore = true,
                    0xf1 | 0xfa => has_call = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_sstore && has_call
    }

    fn lacks_cascade_prevention(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut protection_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                match bytecode[pos - offset] {
                    0x10 | 0x14 => {
                        if pos >= offset + 2 && bytecode[pos - offset - 1] == 0x54 {
                            protection_checks += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        protection_checks < 2
    }
}
