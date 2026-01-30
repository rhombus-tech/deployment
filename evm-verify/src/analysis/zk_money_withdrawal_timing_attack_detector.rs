use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct ZkMoneyWithdrawalTimingAttackDetector;

impl ZkMoneyWithdrawalTimingAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_withdrawal_logic(bytecode, i) && self.lacks_timing_protection(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "ZK Money withdrawal timing attack: timestamp-based withdrawal without timing protection allows correlation attacks".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_withdrawal_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_comparison = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => has_call = true,
                    0x10 | 0x14 => has_comparison = true,
                    _ => {}
                }
            }
        }

        has_call && has_comparison
    }

    fn lacks_timing_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset + 2 < bytecode.len() {
                if bytecode[pos + offset] == 0x20 && bytecode[pos + offset + 1] == 0x54 {
                    return false;
                }
            }
        }
        true
    }
}
