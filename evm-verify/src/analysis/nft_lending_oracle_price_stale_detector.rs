use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct NftLendingOraclePriceStaleDetector;

impl NftLendingOraclePriceStaleDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_oracle_call(bytecode, i) && self.lacks_staleness_check(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "NFT lending oracle price stale: oracle price fetch without staleness check allows stale price exploitation".to_string(),
                    pc: i,
                    confidence: 0.86,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_oracle_call(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_sload = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => has_call = true,
                    0x54 => has_sload = true,
                    _ => {}
                }
            }
        }

        has_call && has_sload
    }

    fn lacks_staleness_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x42 && bytecode[pos + offset + 1] == 0x03 {
                    return false;
                }
            }
        }
        true
    }
}
