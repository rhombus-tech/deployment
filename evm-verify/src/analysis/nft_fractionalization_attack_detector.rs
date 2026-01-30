/// NFT Fractionalization Attack Detector
use crate::bytecode::SecurityFinding;

pub struct NftFractionalizationAttackDetector {
    bytecode: Vec<u8>,
}

impl NftFractionalizationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("NFT fractionalization attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_fractionalization_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_fractionalization_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for NFT fractionalization without proper buyout protection
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // fractionalize, mint (fractional tokens), redeem selectors
            if matches!(self.bytecode[pos+1], 0x40 | 0x6a | 0x84 | 0xdb) {
                let mut has_buyout_mechanism = false;
                let mut has_reserve_price = false;
                let mut has_voting_required = false;
                let mut has_time_lock = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for buyout mechanism (checking if someone can acquire all fractions)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        // Look for total supply check and threshold comparison
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() { // SLOAD
                            if (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) &&
                               self.bytecode[j + 6] == 0x57 { // GT/LT + JUMPI
                                has_buyout_mechanism = true;
                            }
                        }
                    }
                    
                    // Check for reserve price validation
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // REVERT
                                has_reserve_price = true;
                            }
                        }
                    }
                    
                    // Check for voting/governance requirement
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            // Check for vote count or approval count
                            if self.bytecode[j + 3] == 0x10 { // LT check
                                has_voting_required = true;
                            }
                        }
                    }
                    
                    // Check for timelock on critical operations
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) {
                                has_time_lock = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if missing protections against hostile takeovers
                return !has_buyout_mechanism || !has_reserve_price || (!has_voting_required && !has_time_lock);
            }
        }
        false
    }
}
