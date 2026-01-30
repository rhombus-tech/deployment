use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct TornadoCashNovaMerkleTreeManipulationDetector;

impl TornadoCashNovaMerkleTreeManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_merkle_tree_logic(bytecode, i) && self.lacks_tree_validation(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Tornado Cash Nova merkle tree manipulation: merkle tree operations without proper validation allow tree poisoning".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_merkle_tree_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
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

    fn lacks_tree_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 45.min(bytecode.len().saturating_sub(pos));
        let mut validation_count = 0;

        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x14 || bytecode[pos + offset] == 0x10 {
                    validation_count += 1;
                }
            }
        }

        validation_count < 3
    }
}
