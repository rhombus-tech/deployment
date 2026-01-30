use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct VestingLinearUnlockGamingDetector;

impl VestingLinearUnlockGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_linear_vesting(bytecode, i) && self.lacks_rate_limit(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Vesting linear unlock gaming: timestamp-based linear vesting without rate limiting allows gaming".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_linear_vesting(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sub = false;
        let mut has_div = false;
        let mut has_mul = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x03 => has_sub = true,
                    0x04 => has_div = true,
                    0x02 => has_mul = true,
                    _ => {}
                }
            }
        }

        has_sub && has_div && has_mul
    }

    fn lacks_rate_limit(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x54 && bytecode[pos - offset + 1] == 0x10 {
                    return false;
                }
            }
        }
        true
    }
}
