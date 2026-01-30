/// Yearn Vault Strategy Detector
use crate::bytecode::SecurityFinding;

pub struct YearnVaultStrategyDetector {
    bytecode: Vec<u8>,
}

impl YearnVaultStrategyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Yearn vault strategy manipulation at PC {}", location),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.check_strategy_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_strategy_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for harvest() or setStrategy() without proper authorization
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // harvest: 0x4641257d, setStrategy: 0x0e18b681
            if (self.bytecode[pos+1] == 0x46 || self.bytecode[pos+1] == 0x0e) {
                let mut has_role_check = false;
                if pos + 40 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        // Look for role/permission check (SLOAD + comparison)
                        if self.bytecode[j] == 0x54 && j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 4], 0x14 | 0x15) {
                                has_role_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_role_check;
            }
        }
        false
    }
}
