use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct CoinbaseCustodyApiKeyLeakDetector;

impl CoinbaseCustodyApiKeyLeakDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_api_key_logic(bytecode, i) && self.lacks_key_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Coinbase Custody API key leak: API key operations without protection allow key exposure".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_api_key_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_call = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0xf1 | 0xfa | 0xf4 => has_call = true,
                    _ => {}
                }
            }
        }

        has_sload && has_call
    }

    fn lacks_key_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x20 && bytecode[pos - offset + 1] == 0x14 {
                    return false;
                }
            }
        }
        true
    }
}
