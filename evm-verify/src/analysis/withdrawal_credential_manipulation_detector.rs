/// Withdrawal Credential Manipulation Detector
use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalCredentialManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct WithdrawalCredentialManipulationDetector {
    bytecode: Vec<u8>,
}

impl WithdrawalCredentialManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }

    pub fn detect_vulnerabilities(&self) -> Vec<WithdrawalCredentialManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len().saturating_sub(200) {
            if self.detect_pattern(pc) && !self.has_protection(pc, 150) {
                vulnerabilities.push(WithdrawalCredentialManipulationVulnerability {
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: format!("withdrawal credential tampering at PC {}", pc),
                    exploit_scenario: "Manipulate credentials to redirect staking rewards\n\nMitigation: Lock credentials after first set".to_string(),
                    location: pc,
                });
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_pattern(&self, pc: usize) -> bool {
        pc + 100 < self.bytecode.len() && matches!(self.bytecode.get(pc), Some(&0x02) | Some(&0x04) | Some(&0x54) | Some(&0xf1))
    }

    fn has_protection(&self, pc: usize, range: usize) -> bool {
        (pc.saturating_sub(range/2)..pc+range/2).any(|i| matches!(self.bytecode.get(i), Some(&0x10) | Some(&0x11)) && (i+1..i+10).any(|j| self.bytecode.get(j) == Some(&0xfd)))
    }
}
