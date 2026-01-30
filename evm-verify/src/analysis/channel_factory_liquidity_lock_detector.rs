use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct ChannelFactoryLiquidityLockDetector;

impl ChannelFactoryLiquidityLockDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_factory_logic(bytecode, i) && self.lacks_unlock_mechanism(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Channel factory liquidity lock: factory logic without proper unlock mechanism allows fund locking".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_factory_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;
        let mut has_call = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    0xf1 | 0xfa => has_call = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore && has_call
    }

    fn lacks_unlock_mechanism(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut unlock_paths = 0;

        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x14 && bytecode[pos + offset + 1] == 0x57 {
                    unlock_paths += 1;
                }
            }
        }

        unlock_paths < 2
    }
}
