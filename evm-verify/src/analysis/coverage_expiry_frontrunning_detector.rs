use crate::types::{SecurityFinding, Severity};

pub struct CoverageExpiryFrontrunningDetector;

impl CoverageExpiryFrontrunningDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_coverage_expiry_logic(bytecode, i) && self.has_claim_submission(bytecode, i) && self.lacks_expiry_buffer(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: Severity::High,
                        description: "Coverage expiry frontrunning: timestamp-based expiry with immediate claim submission allows frontrunning".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_coverage_expiry_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_jumpi = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x12 => has_comparison = true,
                    0x57 => has_jumpi = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_jumpi
    }

    fn has_claim_submission(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x55 {
                return true;
            }
        }
        false
    }

    fn lacks_expiry_buffer(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x01 && bytecode[pos + offset + 1] == 0x03 {
                    return false;
                }
            }
        }
        true
    }
}
