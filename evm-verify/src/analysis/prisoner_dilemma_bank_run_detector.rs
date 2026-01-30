use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PrisonerDilemmaBankRunDetector;

impl PrisonerDilemmaBankRunDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_withdrawal_function(bytecode, i) {
                if self.has_balance_dependent_value(bytecode, i) && self.lacks_withdrawal_delay(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Prisoner's dilemma bank run vulnerability: balance-dependent withdrawal value without delay creates race to withdraw".to_string(),
                        pc: i,
                        confidence: 0.92,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_withdrawal_function(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0xf1 || op == 0xfa {
                    return true;
                }
            }
        }
        false
    }

    fn has_balance_dependent_value(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_balance = false;
        let mut has_div = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x31 | 0x47 => has_balance = true,
                    0x04 => has_div = true,
                    _ => {}
                }
            }
        }

        has_balance && has_div
    }

    fn lacks_withdrawal_delay(&self, bytecode: &[u8], pos: usize) -> bool {
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
