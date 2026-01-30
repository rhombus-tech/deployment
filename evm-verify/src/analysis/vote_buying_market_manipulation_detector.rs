use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct VoteBuyingMarketManipulationDetector;

impl VoteBuyingMarketManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_voting_mechanism(bytecode, i) && self.has_token_transfer(bytecode, i) && self.lacks_vote_locking(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Vote buying market manipulation vulnerability: voting mechanism with token transfers without vote locking allows vote buying".to_string(),
                    pc: i,
                    confidence: 0.90,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_voting_mechanism(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore
    }

    fn has_token_transfer(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0xf1 || op == 0xfa {
                    return true;
                }
            }
        }
        false
    }

    fn lacks_vote_locking(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x42 && bytecode[pos + offset + 1] == 0x01 {
                    return false;
                }
            }
        }
        true
    }
}
