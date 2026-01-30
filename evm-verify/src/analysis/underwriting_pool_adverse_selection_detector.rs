use crate::types::{SecurityFinding, Severity};

pub struct UnderwritingPoolAdverseSelectionDetector;

impl UnderwritingPoolAdverseSelectionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_underwriting_logic(bytecode, i) && self.lacks_risk_assessment(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: Severity::High,
                    description: "Underwriting pool adverse selection: underwriting without proper risk assessment allows adverse selection".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_underwriting_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sstore = false;
        let mut has_transfer = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x55 => has_sstore = true,
                    0xf1 | 0xfa => has_transfer = true,
                    _ => {}
                }
            }
        }

        has_sstore && has_transfer
    }

    fn lacks_risk_assessment(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut sload_count = 0;
        let mut comparison_count = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => sload_count += 1,
                    0x10 | 0x12 => comparison_count += 1,
                    _ => {}
                }
            }
        }

        sload_count < 2 || comparison_count < 2
    }
}
