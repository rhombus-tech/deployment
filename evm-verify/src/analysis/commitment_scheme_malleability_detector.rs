/// Commitment Scheme Malleability Detector
use crate::bytecode::SecurityFinding;

pub struct CommitmentSchemeMalleabilityDetector {
    bytecode: Vec<u8>,
}

impl CommitmentSchemeMalleabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_weak_commitment() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Commitment uses weak hash vulnerable to malleability at PC {}", pc),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_weak_commitment(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x4a | 0x5b) {
                    let mut has_keccak = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // KECCAK256
                            has_keccak = true;
                        }
                    }
                    if !has_keccak {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
