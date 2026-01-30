/// Liquid Democracy Attack Detector
use crate::bytecode::SecurityFinding;

pub struct LiquidDemocracyAttackDetector {
    bytecode: Vec<u8>,
}

impl LiquidDemocracyAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Liquid democracy transitive voting attack at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_transitive_voting_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_transitive_voting_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for transitive delegation without proper cycle/depth protection
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getDelegatedVotes, resolveVoting, transitiveDelegate selectors
            if matches!(self.bytecode[pos+1], 0x4a | 0x6b | 0x8c | 0xd1) {
                let mut has_recursion_limit = false;
                let mut has_cycle_detection = false;
                let mut has_weight_calculation = false;
                let mut validates_delegation_chain = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for recursion/depth limit (counter + GT check)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_recursion_limit = true;
                            }
                        }
                    }
                    
                    // Check for cycle detection (visited set or comparison chain)
                    let mut comparison_count = 0;
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 { // EQ (checking if already visited)
                            comparison_count += 1;
                        }
                    }
                    if comparison_count >= 2 {
                        has_cycle_detection = true;
                    }
                    
                    // Check for proper vote weight calculation (MUL/DIV operations)
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 && j + 4 < self.bytecode.len() { // MUL
                            if self.bytecode[j + 2] == 0x04 { // DIV
                                has_weight_calculation = true;
                            }
                        }
                    }
                    
                    // Check if validates each step in delegation chain
                    let mut sload_count = 0;
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD (reading delegates)
                            sload_count += 1;
                        }
                    }
                    if sload_count >= 3 {
                        validates_delegation_chain = true;
                    }
                }
                
                // Vulnerable if transitive voting without safeguards
                // Attacks: cycle creation, unbounded recursion, vote weight manipulation
                return !has_recursion_limit || !has_cycle_detection || !has_weight_calculation || !validates_delegation_chain;
            }
        }
        false
    }
}
