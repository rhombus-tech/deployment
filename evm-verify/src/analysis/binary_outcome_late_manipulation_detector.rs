use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct BinaryOutcomeLateManipulationDetector;

impl BinaryOutcomeLateManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_binary_outcome_logic(bytecode, i) && self.lacks_trading_freeze(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Binary outcome late manipulation: timestamp-based binary outcome without trading freeze allows late manipulation".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_binary_outcome_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_jumpi = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => has_comparison = true,
                    0x57 => has_jumpi = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_jumpi
    }

    fn lacks_trading_freeze(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x03 && bytecode[pos + offset + 1] == 0x10 {
                    return false;
                }
            }
        }
        true
    }
}
