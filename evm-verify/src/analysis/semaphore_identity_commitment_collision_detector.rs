use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct SemaphoreIdentityCommitmentCollisionDetector;

impl SemaphoreIdentityCommitmentCollisionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_identity_commitment(bytecode, i) && self.lacks_collision_resistance(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Semaphore identity commitment collision: identity commitment without collision resistance allows identity spoofing".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_identity_commitment(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_keccak = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => has_keccak = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_keccak && has_sstore
    }

    fn lacks_collision_resistance(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut uniqueness_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => uniqueness_checks += 1,
                    _ => {}
                }
            }
        }

        uniqueness_checks < 2
    }
}
