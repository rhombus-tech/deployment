use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct BlsSignatureAggregationMalleabilityDetector;

impl BlsSignatureAggregationMalleabilityDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_bls_aggregation(bytecode, i) && self.lacks_malleability_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "BLS signature aggregation malleability: signature aggregation without malleability protection allows signature forgery".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_bls_aggregation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_call = false;
        let mut has_keccak = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa | 0xf4 => has_call = true,
                    0x20 => has_keccak = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_call && has_keccak && has_sstore
    }

    fn lacks_malleability_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut uniqueness_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 | 0x14 => uniqueness_checks += 1,
                    _ => {}
                }
            }
        }

        uniqueness_checks < 3
    }
}
