/// Challenge Period Griefing Detector
use crate::bytecode::SecurityFinding;

pub struct ChallengePeriodGriefingDetector {
    bytecode: Vec<u8>,
}

impl ChallengePeriodGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Challenge period griefing vulnerability at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_challenge_griefing(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_challenge_griefing(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for challenge mechanism that can be griefed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // challenge, dispute, contestStateRoot selectors
            if matches!(self.bytecode[pos+1], 0x27 | 0x4d | 0x71 | 0xb5) {
                let mut has_bond_requirement = false;
                let mut prevents_spam_challenges = false;
                let mut has_challenge_cost = false;
                let mut limits_concurrent_challenges = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for bond/stake requirement
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x31 && j + 6 < self.bytecode.len() { // BALANCE
                            if self.bytecode[j + 3] == 0x10 { // LT (checking minimum bond)
                                has_bond_requirement = true;
                            }
                        }
                    }
                    
                    // Check for spam prevention (cooldown, rate limiting)
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 8 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 4] == 0x01 { // ADD (cooldown calculation)
                                prevents_spam_challenges = true;
                            }
                        }
                    }
                    
                    // Check for challenge cost (gas/fee)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 { // CALL (payment required)
                            has_challenge_cost = true;
                        }
                    }
                    
                    // Check for concurrent challenge limit
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 3] == 0x11 { // GT (checking count limit)
                                limits_concurrent_challenges = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if challenge system can be griefed via:
                // 1. No bond requirement (free challenges)
                // 2. No spam prevention
                // 3. No cost to challenge
                // 4. Unlimited concurrent challenges
                return !has_bond_requirement || !prevents_spam_challenges || !has_challenge_cost || !limits_concurrent_challenges;
            }
        }
        false
    }
}
