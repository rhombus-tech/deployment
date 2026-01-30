/// Vote Delegation Attack Detector
use crate::bytecode::SecurityFinding;

pub struct VoteDelegationAttackDetector {
    bytecode: Vec<u8>,
}

impl VoteDelegationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Vote delegation attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_delegation_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_delegation_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for vote delegation without proper safeguards
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // delegate, delegateBySig, delegateVotes selectors
            if matches!(self.bytecode[pos+1], 0x5c | 0x6f | 0x7d | 0xbf) {
                let mut has_cycle_check = false;
                let mut has_delegation_limit = false;
                let mut has_timestamp_check = false;
                let mut checks_delegate_exists = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for cycle detection (comparing delegatee to previous delegates)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() { // SLOAD
                            // Should check if delegatee is already in chain
                            if self.bytecode[j + 4] == 0x14 && matches!(self.bytecode[j + 6], 0x57 | 0xfd) {
                                has_cycle_check = true;
                            }
                        }
                    }
                    
                    // Check for delegation depth/chain length limit
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_delegation_limit = true;
                            }
                        }
                    }
                    
                    // Check for timestamp/block validation (prevent flashloan governance)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 || self.bytecode[j] == 0x43 { // TIMESTAMP/NUMBER
                            has_timestamp_check = true;
                        }
                    }
                    
                    // Check if validates delegate address is not zero/valid
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x15 && j + 3 < self.bytecode.len() { // ISZERO
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                checks_delegate_exists = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if:
                // 1. No cycle detection (A->B->C->A)
                // 2. No delegation depth limit (can create very long chains)
                // 3. No timestamp check (instant delegation + vote)
                // 4. Doesn't validate delegate address
                return !has_cycle_check || !has_delegation_limit || !has_timestamp_check || !checks_delegate_exists;
            }
        }
        false
    }
}
