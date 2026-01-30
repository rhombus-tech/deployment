/// Smart Wallet Module Reentrancy Detector
use crate::bytecode::SecurityFinding;

pub struct ModuleReentrancyDetector {
    bytecode: Vec<u8>,
}

impl ModuleReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Smart wallet module reentrancy vulnerability at PC {}", location),
                pc: location,
                confidence: 0.92,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_module_reentrancy(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_module_reentrancy(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for module execution without reentrancy guard (ERC-4337/Safe style)
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // executeFromModule, execTransactionFromModule selectors
            if matches!(self.bytecode[pos+1], 0x46 | 0x5f | 0x61 | 0x8d) {
                let mut has_reentrancy_guard = false;
                let mut has_module_auth_check = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for reentrancy guard (SLOAD + ISZERO + REVERT pattern)
                    for j in (pos + 5)..(pos + 25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 2] == 0x15 && matches!(self.bytecode[j + 4], 0x57 | 0xfd) {
                                has_reentrancy_guard = true;
                            }
                        }
                    }
                    
                    // Check for module authorization (CALLER + SLOAD comparison)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 && j + 8 < self.bytecode.len() { // CALLER
                            if self.bytecode[j + 3] == 0x54 && self.bytecode[j + 5] == 0x14 { // SLOAD + EQ
                                has_module_auth_check = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if missing reentrancy guard or weak module auth
                return !has_reentrancy_guard || !has_module_auth_check;
            }
        }
        false
    }
}
