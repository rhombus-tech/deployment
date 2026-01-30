use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct InitialBondingCurveManipulationDetector;

impl InitialBondingCurveManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_bonding_curve(bytecode, i) && self.lacks_initial_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Initial bonding curve manipulation: bonding curve without initial protection allows early manipulation".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_bonding_curve(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_mul = false;
        let mut has_div = false;
        let mut has_sload = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => has_mul = true,
                    0x04 => has_div = true,
                    0x54 => has_sload = true,
                    _ => {}
                }
            }
        }

        has_mul && has_div && has_sload
    }

    fn lacks_initial_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut timestamp_check = false;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x42 && bytecode[pos - offset + 1] == 0x10 {
                    timestamp_check = true;
                    break;
                }
            }
        }

        !timestamp_check
    }
}
