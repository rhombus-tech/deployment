use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct SearcherCompetitionDosDetector;

impl SearcherCompetitionDosDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_competition_logic(bytecode, i) && self.lacks_dos_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Medium,
                    description: "Searcher competition DoS: competition logic without DoS protection allows griefing".to_string(),
                    pc: i,
                    confidence: 0.82,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_competition_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_call = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => has_comparison = true,
                    0xf1 | 0xfa => has_call = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_call && has_sstore
    }

    fn lacks_dos_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x5a && bytecode[pos - offset + 1] == 0x10 {
                    return false;
                }
            }
        }
        true
    }
}
