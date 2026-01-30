use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct FairLaunchBotSnipingDetector;

impl FairLaunchBotSnipingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_launch_logic(bytecode, i) && self.lacks_bot_protection(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Fair launch bot sniping: timestamp-based launch without bot protection allows sniping".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_launch_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_sstore = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x12 => has_comparison = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_sstore
    }

    fn lacks_bot_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x32 && bytecode[pos + offset + 1] == 0x3a {
                    return false;
                }
            }
        }
        true
    }
}
