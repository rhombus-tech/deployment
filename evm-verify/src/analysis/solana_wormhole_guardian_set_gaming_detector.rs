use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct SolanaWormholeGuardianSetGamingDetector;

impl SolanaWormholeGuardianSetGamingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_guardian_set_logic(bytecode, i) && self.lacks_gaming_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Solana Wormhole guardian set gaming: guardian set updates without gaming protection allow bridge compromise".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_guardian_set_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;
        let mut has_ecrecover = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    0x01 if pos + offset + 1 < bytecode.len() && bytecode[pos + offset + 1] == 0xf4 => has_ecrecover = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore && has_ecrecover
    }

    fn lacks_gaming_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut quorum_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x10 || bytecode[pos - offset] == 0x12 {
                    quorum_checks += 1;
                }
            }
        }

        quorum_checks < 2
    }
}
