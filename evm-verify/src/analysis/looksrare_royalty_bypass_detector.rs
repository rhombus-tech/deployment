/// LooksRare Royalty Bypass Detector
/// Detects royalty payment bypass in marketplace contracts
use crate::bytecode::SecurityFinding;

pub struct LooksrareRoyaltyBypassDetector {
    bytecode: Vec<u8>,
}

impl LooksrareRoyaltyBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.has_royalty_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Royalty bypass vulnerability at PC {}. Marketplace sale without enforced royalty payment",
                    location
                ),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn has_royalty_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0xf1 { // CALL (transfer)
                let has_royalty = self.has_royalty_calculation_before(i);
                if !has_royalty {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_royalty_calculation_before(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(80);
        for i in start..pos {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x02 && i + 3 < self.bytecode.len() && self.bytecode[i+2] == 0x04 { return true; }
        }
        false
    }
}
