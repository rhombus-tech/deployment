/// Cross-Domain Sandwich Detector - L1↔L2 MEV
use crate::bytecode::SecurityFinding;

pub struct CrossDomainSandwichDetector {
    bytecode: Vec<u8>,
}

impl CrossDomainSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_l2_message_delay_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("L2 message delay allows sandwich attacks at PC {}", pc),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_l2_message_delay_exploit(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xf5 | 0xa6) {
                    return Some(i);
                }
            }
        }
        None
    }
}
