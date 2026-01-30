use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FractionalizedNftShareManipulationDetector;

impl FractionalizedNftShareManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_fractionalization(bytecode, i) && self.lacks_share_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Fractionalized NFT share manipulation: fractionalization without share protection allows manipulation".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_fractionalization(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_div = false;
        let mut has_sstore = false;
        let mut has_sload = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x04 => has_div = true,
                    0x55 => has_sstore = true,
                    0x54 => has_sload = true,
                    _ => {}
                }
            }
        }

        has_div && has_sstore && has_sload
    }

    fn lacks_share_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut comparison_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x12 | 0x14 => comparison_count += 1,
                    _ => {}
                }
            }
        }

        comparison_count < 2
    }
}
