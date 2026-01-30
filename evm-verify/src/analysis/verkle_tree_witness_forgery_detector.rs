use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct VerkleTreeWitnessForgeryDetector;

impl VerkleTreeWitnessForgeryDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_verkle_tree_logic(bytecode, i) && self.lacks_forgery_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Verkle tree witness forgery: verkle tree operations without forgery protection allow state proof manipulation".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_verkle_tree_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_keccak = false;
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => has_keccak = true,
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_keccak && has_sload && has_sstore
    }

    fn lacks_forgery_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut verification_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x10 | 0x14 | 0x20 => verification_checks += 1,
                    _ => {}
                }
            }
        }

        verification_checks < 3
    }
}
