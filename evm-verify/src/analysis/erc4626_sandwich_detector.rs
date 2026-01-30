/// ERC4626 Sandwich Detector
use crate::bytecode::SecurityFinding;

pub struct Erc4626SandwichDetector {
    bytecode: Vec<u8>,
}

impl Erc4626SandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("ERC4626 vault sandwich attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_vault_sandwich(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_vault_sandwich(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // deposit: 0x6e553f65, mint: 0x94bf804d, withdraw: 0xb460af94, redeem: 0xba087652
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            let is_vault_op = (self.bytecode[pos+1] == 0x6e && self.bytecode[pos+2] == 0x55) ||
                             (self.bytecode[pos+1] == 0x94 && self.bytecode[pos+2] == 0xbf) ||
                             (self.bytecode[pos+1] == 0xb4 && self.bytecode[pos+2] == 0x60) ||
                             (self.bytecode[pos+1] == 0xba && self.bytecode[pos+2] == 0x08);
            
            if is_vault_op && pos + 50 < self.bytecode.len() {
                let mut has_slippage_protection = false;
                for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT check
                        if j + 4 < self.bytecode.len() && matches!(self.bytecode[j + 3], 0xfd | 0x57) {
                            has_slippage_protection = true;
                            break;
                        }
                    }
                }
                return !has_slippage_protection;
            }
        }
        false
    }
}
