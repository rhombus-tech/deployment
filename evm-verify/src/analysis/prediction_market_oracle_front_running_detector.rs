/// Prediction Market Oracle Front-Running Detector
use crate::bytecode::SecurityFinding;

pub struct PredictionMarketOracleFrontRunningDetector {
    bytecode: Vec<u8>,
}

impl PredictionMarketOracleFrontRunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_resolution_frontrun() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Market resolution lacks commit-reveal, frontrunnable at PC {}", pc),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_resolution_frontrun(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xe5 | 0xf6) { // resolve
                    let mut has_commit = false;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // KECCAK256 (commit hash)
                            has_commit = true;
                        }
                    }
                    if !has_commit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
