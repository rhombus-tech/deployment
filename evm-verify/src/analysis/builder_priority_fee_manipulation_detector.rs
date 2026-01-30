use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct BuilderPriorityFeeManipulationDetector;

impl BuilderPriorityFeeManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_fee_logic(bytecode, i) && self.lacks_manipulation_check(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Builder priority fee manipulation: fee logic without manipulation check allows unfair extraction".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_fee_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_mul = false;
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => has_mul = true,
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_mul && has_sload && has_sstore
    }

    fn lacks_manipulation_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut comparison_count = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x10 | 0x14 => comparison_count += 1,
                    _ => {}
                }
            }
        }

        comparison_count < 2
    }
}
