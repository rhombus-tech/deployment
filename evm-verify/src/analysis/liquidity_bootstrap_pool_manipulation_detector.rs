use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct LiquidityBootstrapPoolManipulationDetector;

impl LiquidityBootstrapPoolManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_weight_adjustment(bytecode, i) && self.lacks_manipulation_check(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Liquidity bootstrap pool manipulation: weight adjustment without manipulation protection allows price gaming".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_weight_adjustment(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_mul = false;
        let mut has_div = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => has_mul = true,
                    0x04 => has_div = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_mul && has_div && has_sstore
    }

    fn lacks_manipulation_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
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
