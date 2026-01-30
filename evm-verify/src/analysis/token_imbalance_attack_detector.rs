/// Token Imbalance Attack Detector
/// Detects AMM pool manipulation through token imbalance
use crate::bytecode::SecurityFinding;

pub struct TokenImbalanceAttackDetector {
    bytecode: Vec<u8>,
}

impl TokenImbalanceAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_unbalanced_swap() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Token imbalance vulnerability at PC {}. AMM swap without proper balance ratio checks allows pool manipulation",
                    location
                ),
                pc: location,
                confidence: 0.86,
            });
        }

        findings
    }

    fn has_unbalanced_swap(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x54 { // SLOAD (reading reserves)
                let has_swap = self.has_swap_operation_after(i);
                let has_ratio_check = self.has_balance_ratio_check(i);
                
                if has_swap && !has_ratio_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_swap_operation_after(&self, pos: usize) -> bool {
        let end = (pos + 100).min(self.bytecode.len());
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x02 || self.bytecode[i] == 0x04 { // MUL or DIV
                return true;
            }
        }
        false
    }

    fn has_balance_ratio_check(&self, pos: usize) -> bool {
        let end = (pos + 80).min(self.bytecode.len());
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT (ratio comparison)
                return true;
            }
        }
        false
    }
}
