/// Rocket Pool Minipool Validator Detector
use crate::bytecode::SecurityFinding;

pub struct RocketpoolMinipoolDetector {
    bytecode: Vec<u8>,
}

impl RocketpoolMinipoolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Rocket Pool minipool validator manipulation at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_minipool_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_minipool_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for stake/withdraw operations without node operator validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // stake selector: 0x3a4b66f1, withdraw: 0x2e1a7d4d
            if (self.bytecode[pos+1] == 0x3a || self.bytecode[pos+1] == 0x2e) {
                // Check for node operator address validation (CALLER comparison)
                let mut has_operator_check = false;
                if pos + 35 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 { // CALLER
                            if j + 3 < self.bytecode.len() && self.bytecode[j + 2] == 0x14 { // EQ
                                has_operator_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_operator_check;
            }
        }
        false
    }
}
