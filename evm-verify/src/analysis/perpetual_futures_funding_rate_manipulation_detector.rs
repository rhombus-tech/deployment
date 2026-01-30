/// Perpetual Futures Funding Rate Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct PerpetualFuturesFundingRateManipulationDetector {
    bytecode: Vec<u8>,
}

impl PerpetualFuturesFundingRateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_funding_rate_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Funding rate calculated from single oracle, manipulable at PC {}", pc),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_funding_rate_oracle_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xa1 | 0xb2) { // updateFundingRate
                    let mut oracle_calls = 0;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            oracle_calls += 1;
                        }
                    }
                    if oracle_calls < 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
