use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FreeRiderRewardGamingDetector;

impl FreeRiderRewardGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_reward_distribution(bytecode, i) && self.lacks_contribution_verification(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Free rider reward gaming vulnerability: reward distribution without contribution verification allows gaming".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_reward_distribution(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_balance_check = false;
        let mut has_transfer = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x31 | 0x47 => has_balance_check = true,
                    0xf1 | 0xfa => has_transfer = true,
                    _ => {}
                }
            }
        }

        has_balance_check && has_transfer
    }

    fn lacks_contribution_verification(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_sload = false;
        let mut has_comparison = false;

        for offset in 1..=lookback {
            if pos >= offset && bytecode[pos - offset] == 0x54 {
                has_sload = true;
            }
            if pos >= offset {
                let op = bytecode[pos - offset];
                if op == 0x10 || op == 0x12 || op == 0x14 {
                    has_comparison = true;
                }
            }
        }

        !has_sload || !has_comparison
    }
}
