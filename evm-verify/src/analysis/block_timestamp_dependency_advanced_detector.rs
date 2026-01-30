use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct BlockTimestampDependencyAdvancedDetector;

impl BlockTimestampDependencyAdvancedDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.is_timestamp_in_randomness(bytecode, i)
                    || self.is_timestamp_in_critical_logic(bytecode, i)
                    || self.is_timestamp_exact_equality(bytecode, i)
                {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Advanced timestamp dependency detected: timestamp used in randomness generation, exact equality checks, or critical state transitions".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn is_timestamp_in_randomness(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x20 {
                return true;
            }
        }
        false
    }

    fn is_timestamp_in_critical_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 15.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0x55 || op == 0xf0 || op == 0xf1 {
                    return true;
                }
            }
        }
        false
    }

    fn is_timestamp_exact_equality(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 5.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x14 {
                return true;
            }
        }
        false
    }
}
