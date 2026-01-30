use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct QuadraticVotingCollusionRingDetector;

impl QuadraticVotingCollusionRingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_quadratic_voting(bytecode, i) && self.lacks_collusion_detection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Quadratic voting collusion ring: quadratic voting without collusion detection allows sybil attacks".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_quadratic_voting(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_mul = false;
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => has_mul = true,
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_mul && has_sload && has_sstore
    }

    fn lacks_collusion_detection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut identity_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x14 || bytecode[pos - offset] == 0x33 {
                    identity_checks += 1;
                }
            }
        }

        identity_checks < 2
    }
}
