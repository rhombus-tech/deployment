/// Insurance Pool Solvency Detector
use crate::bytecode::SecurityFinding;

pub struct InsurancePoolSolvencyDetector {
    bytecode: Vec<u8>,
}

impl InsurancePoolSolvencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_underfunded_payout() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Insurance payout lacks reserve sufficiency check at PC {}", pc),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_underfunded_payout(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xa7 | 0xb8) { // claimPayout
                    let mut has_balance_check = false;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x31 { // BALANCE
                            has_balance_check = true;
                        }
                    }
                    if !has_balance_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
