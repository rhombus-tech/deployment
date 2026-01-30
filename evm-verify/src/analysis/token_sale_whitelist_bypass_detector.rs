use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct TokenSaleWhitelistBypassDetector;

impl TokenSaleWhitelistBypassDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_whitelist_check(bytecode, i) && self.has_bypass_possibility(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Token sale whitelist bypass: whitelist check with bypass possibility allows unauthorized access".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_whitelist_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x14 => has_comparison = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison
    }

    fn has_bypass_possibility(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut jumpi_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x57 {
                jumpi_count += 1;
            }
        }

        jumpi_count > 1
    }
}
