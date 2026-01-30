use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct AnchorageSmartContractCustodyBypassDetector;

impl AnchorageSmartContractCustodyBypassDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_custody_logic(bytecode, i) && self.lacks_bypass_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Anchorage smart contract custody bypass: custody logic without bypass protection allows unauthorized withdrawals".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_custody_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;
        let mut has_call = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x14 => has_comparison = true,
                    0xf1 | 0xfa => has_call = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison && has_call
    }

    fn lacks_bypass_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut protection_layers = 0;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x57 {
                    protection_layers += 1;
                }
            }
        }

        protection_layers < 2
    }
}
