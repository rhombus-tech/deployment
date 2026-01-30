use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct CopperCustodyColdStorageBridgeDetector;

impl CopperCustodyColdStorageBridgeDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_cold_storage_bridge(bytecode, i) && self.lacks_bridge_security(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Copper custody cold storage bridge: cold storage bridge without security checks allows unauthorized access".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_cold_storage_bridge(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => has_call = true,
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_call && has_sload && has_sstore
    }

    fn lacks_bridge_security(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut security_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x33 | 0x32 | 0x14 => security_checks += 1,
                    _ => {}
                }
            }
        }

        security_checks < 3
    }
}
