/// MEV Blocker Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct MevBlockerBypassDetector {
    bytecode: Vec<u8>,
}

impl MevBlockerBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("MEV blocker bypass vulnerability at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_mev_blocker_bypass(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_mev_blocker_bypass(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for MEV protection mechanisms that can be bypassed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // swap, execute, trade selectors
            if matches!(self.bytecode[pos+1], 0x12 | 0x38 | 0x54 | 0xa9) {
                let mut checks_coinbase = false;
                let mut validates_builder = false;
                let mut has_slippage_protection = false;
                let mut prevents_sandwich = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for coinbase validation (block.coinbase check)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x41 { // COINBASE
                            checks_coinbase = true;
                        }
                    }
                    
                    // Check for builder whitelist validation
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 3] == 0x14 { // EQ (checking whitelist)
                                validates_builder = true;
                            }
                        }
                    }
                    
                    // Check for slippage protection
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                            has_slippage_protection = true;
                        }
                    }
                    
                    // Check for sandwich attack prevention (deadline, private mempool)
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 3] == 0x10 { // LT (deadline check)
                                prevents_sandwich = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if MEV blocker can be bypassed via:
                // 1. Manipulating coinbase checks
                // 2. Bypassing builder whitelist
                // 3. No slippage protection
                // 4. Sandwich attacks still possible
                return !checks_coinbase || !validates_builder || !has_slippage_protection || !prevents_sandwich;
            }
        }
        false
    }
}
