/// Euler Finance 2023 Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct EulerFinance2023Detector {
    bytecode: Vec<u8>,
}

impl EulerFinance2023Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Euler-style donation attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.90,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_donation_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_donation_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for donateToReserves pattern or liquidation without health check
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // Look for balance manipulation through donations
            if pos + 50 < self.bytecode.len() {
                let mut updates_reserves = false;
                let mut has_health_check = false;
                
                for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                    // Check for SSTORE (updating reserves/balances)
                    if self.bytecode[j] == 0x55 {
                        updates_reserves = true;
                    }
                    // Check for health factor validation
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT
                        if j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0xfd | 0x57) {
                                has_health_check = true;
                            }
                        }
                    }
                }
                
                return updates_reserves && !has_health_check;
            }
        }
        false
    }
}
