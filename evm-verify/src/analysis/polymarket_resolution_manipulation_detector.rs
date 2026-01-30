use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PolymarketResolutionManipulationDetector;

impl PolymarketResolutionManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_resolution_logic(bytecode, i) && self.lacks_dispute_period(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Polymarket resolution manipulation: market resolution without dispute period allows manipulation".to_string(),
                    pc: i,
                    confidence: 0.90,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_resolution_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sstore = false;
        let mut has_comparison = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x55 => has_sstore = true,
                    0x10 | 0x14 => has_comparison = true,
                    _ => {}
                }
            }
        }

        has_sstore && has_comparison
    }

    fn lacks_dispute_period(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x42 && bytecode[pos + offset + 1] == 0x01 {
                    return false;
                }
            }
        }
        true
    }
}
