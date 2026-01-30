use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct SplitDelegationAttackDetector;

impl SplitDelegationAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_split_delegation(bytecode, i) && self.lacks_split_validation(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Split delegation attack: split delegation without validation allows vote weight manipulation".to_string(),
                    pc: i,
                    confidence: 0.85,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_split_delegation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_div = false;
        let mut has_sstore = false;
        let mut sstore_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x04 => has_div = true,
                    0x55 => {
                        has_sstore = true;
                        sstore_count += 1;
                    }
                    _ => {}
                }
            }
        }

        has_div && has_sstore && sstore_count > 1
    }

    fn lacks_split_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut validation_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => validation_count += 1,
                    _ => {}
                }
            }
        }

        validation_count < 2
    }
}
