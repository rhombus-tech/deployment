use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct UnlockScheduleGamingDetector;

impl UnlockScheduleGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_schedule_calculation(bytecode, i) && self.lacks_fairness_delay(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unlock schedule gaming vulnerability: timestamp-based unlock calculation without fairness delay allows gaming".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_schedule_calculation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_mul = false;
        let mut has_div = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => has_mul = true,
                    0x04 => has_div = true,
                    _ => {}
                }
            }
        }

        has_mul && has_div
    }

    fn lacks_fairness_delay(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x01 && bytecode[pos + offset + 1] == 0x42 {
                    return false;
                }
            }
        }
        true
    }
}
