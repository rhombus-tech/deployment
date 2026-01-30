use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct VestingCliffFrontrunningDetector;

impl VestingCliffFrontrunningDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_vesting_unlock_logic(bytecode, i) && self.has_token_transfer(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Vesting cliff frontrunning vulnerability: timestamp-based unlock followed by immediate token transfer allows frontrunning".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_vesting_unlock_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_jumpi = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x12 => has_comparison = true,
                    0x57 => has_jumpi = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_jumpi
    }

    fn has_token_transfer(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xf1 || bytecode[pos + offset] == 0xfa {
                    return true;
                }
            }
        }
        false
    }
}
