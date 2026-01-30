/// Rage Quit Attack Detector (Moloch-style DAOs)
use crate::bytecode::SecurityFinding;

pub struct RageQuitAttackDetector {
    bytecode: Vec<u8>,
}

impl RageQuitAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Rage quit attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_rage_quit_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_rage_quit_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for ragequit/emergency exit without proper safeguards
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // ragequit, emergencyExit, withdraw selectors
            if matches!(self.bytecode[pos+1], 0x3e | 0x6f | 0xa2 | 0xcc) {
                let mut has_proposal_check = false;
                let mut has_grace_period = false;
                let mut has_proportional_share = false;
                let mut prevents_draining = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for active proposal validation
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            // Check if validates no proposals are pending
                            if self.bytecode[j + 3] == 0x15 { // ISZERO
                                has_proposal_check = true;
                            }
                        }
                    }
                    
                    // Check for grace period (TIMESTAMP comparison)
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) {
                                has_grace_period = true;
                            }
                        }
                    }
                    
                    // Check for proportional share calculation (not taking everything)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 { // DIV (calculating share)
                            has_proportional_share = true;
                        }
                    }
                    
                    // Check for limits preventing complete drain
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            // Should check minimum remaining funds
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                prevents_draining = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if:
                // 1. Can ragequit during active proposals
                // 2. No grace period for other members to react
                // 3. Can drain disproportionate share
                // 4. No minimum DAO balance requirement
                return !has_proposal_check || !has_grace_period || !has_proportional_share || !prevents_draining;
            }
        }
        false
    }
}
