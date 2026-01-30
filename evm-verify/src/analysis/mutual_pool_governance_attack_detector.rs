use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct MutualPoolGovernanceAttackDetector;

impl MutualPoolGovernanceAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_governance_mechanism(bytecode, i) && self.has_pool_control(bytecode, i) && self.lacks_quorum_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Mutual pool governance attack: governance mechanism with pool control without quorum protection allows governance takeover".to_string(),
                    pc: i,
                    confidence: 0.89,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_governance_mechanism(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_comparison = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x10 | 0x12 => has_comparison = true,
                    _ => {}
                }
            }
        }

        has_sload && has_comparison
    }

    fn has_pool_control(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x55 {
                return true;
            }
        }
        false
    }

    fn lacks_quorum_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut div_count = 0;
        let mut comparison_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x04 => div_count += 1,
                    0x10 | 0x12 => comparison_count += 1,
                    _ => {}
                }
            }
        }

        div_count == 0 || comparison_count < 2
    }
}
