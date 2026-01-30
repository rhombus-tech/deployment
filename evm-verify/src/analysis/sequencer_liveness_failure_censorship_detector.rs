use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct SequencerLivenessFailureCensorshipDetector;

impl SequencerLivenessFailureCensorshipDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_sequencer_logic(bytecode, i) && self.lacks_liveness_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Sequencer liveness failure censorship: sequencer logic without liveness checks allows censorship".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_sequencer_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;
        let mut has_sstore = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x14 => has_comparison = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison && has_sstore
    }

    fn lacks_liveness_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut fallback_checks = 0;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x57 => fallback_checks += 1,
                    _ => {}
                }
            }
        }

        fallback_checks < 2
    }
}
