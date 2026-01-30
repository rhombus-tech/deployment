use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct ConvictionVotingManipulationDetector;

impl ConvictionVotingManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_conviction_logic(bytecode, i) && self.lacks_manipulation_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Conviction voting manipulation: timestamp-based conviction accumulation without manipulation checks allows vote gaming".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_conviction_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sub = false;
        let mut has_mul = false;
        let mut has_sstore = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x03 => has_sub = true,
                    0x02 => has_mul = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sub && has_mul && has_sstore
    }

    fn lacks_manipulation_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut validation_count = 0;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => validation_count += 1,
                    _ => {}
                }
            }
        }

        validation_count < 2
    }
}
