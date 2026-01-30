use crate::bytecode::SecurityFinding;

pub struct TrustGraphPoisoningDetector {
    bytecode: Vec<u8>,
}

impl TrustGraphPoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_unbounded_trust_propagation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Trust graph allows unbounded trust propagation at PC {}. \
                    Malicious actors can amplify trust through circular references.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_missing_cycle_detection() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Trust graph missing cycle detection at PC {}. \
                    Attackers can create circular trust relationships to game reputation.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_trust_decay_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Trust decay can be manipulated via timestamp-based calculations at PC {}. \
                    Attackers may preserve or artificially boost trust scores.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_unbounded_trust_propagation(&self) -> Option<usize> {
        // Look for trust propagation without depth limits
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getTrustScore, calculateTrust, propagateTrust selectors
                if matches!(selector, [0x7a, 0x4d, _, _] | [0x8b, 0x5f, _, _] | [0x9c, 0x71, _, _]) {
                    let mut has_depth_limit = false;
                    let mut has_recursion = false;
                    let mut has_loop = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for depth counter (comparing against max depth)
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD or variable load
                               (j + 3 < self.bytecode.len() && 
                                (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11)) { // LT or GT
                                has_depth_limit = true;
                            }
                        }
                        // Check for recursive call pattern (CALL to same contract)
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x30 && // ADDRESS (current contract)
                               j + 8 < self.bytecode.len() &&
                               (self.bytecode[j + 8] == 0xf1 || self.bytecode[j + 8] == 0xfa) { // CALL or STATICCALL
                                has_recursion = true;
                            }
                        }
                        // Check for loop (JUMPDEST followed by JUMP back)
                        if j + 20 < self.bytecode.len() {
                            if self.bytecode[j] == 0x5b { // JUMPDEST
                                for k in j..j + 20 {
                                    if self.bytecode[k] == 0x56 || self.bytecode[k] == 0x57 { // JUMP or JUMPI
                                        has_loop = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    if (has_recursion || has_loop) && !has_depth_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_missing_cycle_detection(&self) -> Option<usize> {
        // Look for trust graph updates without cycle detection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // addTrust, setTrust, endorseUser selectors
                if matches!(selector, [0x5d, 0x3a, _, _] | [0x6f, 0x4b, _, _] | [0x7e, 0x9c, _, _]) {
                    let mut has_cycle_check = false;
                    let mut has_visited_tracking = false;
                    let mut stores_trust = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for visited nodes tracking (bitmap or mapping)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD (checking if node visited)
                                let mut has_comparison = false;
                                for k in j..j + 8 {
                                    if self.bytecode[k] == 0x14 || self.bytecode[k] == 0x15 { // EQ or ISZERO
                                        has_comparison = true;
                                    }
                                    if self.bytecode[k] == 0x55 { // SSTORE (marking as visited)
                                        has_visited_tracking = true;
                                    }
                                }
                                if has_comparison && has_visited_tracking {
                                    has_cycle_check = true;
                                }
                            }
                        }
                        // Check for external cycle detection call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // hasCycle, detectCycle selectors
                            if matches!(sub_selector, [0xa1, 0x2f, _, _] | [0xb3, 0x4d, _, _]) {
                                has_cycle_check = true;
                            }
                        }
                        // Check if trust relationship is stored
                        if self.bytecode[j] == 0x55 { // SSTORE
                            stores_trust = true;
                        }
                    }
                    
                    if stores_trust && !has_cycle_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_trust_decay_manipulation(&self) -> Option<usize> {
        // Look for trust decay calculations vulnerable to timestamp manipulation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getTrustScore, calculateDecay, getEffectiveTrust selectors
                if matches!(selector, [0x7a, 0x4d, _, _] | [0x8c, 0x6e, _, _] | [0x9d, 0x7f, _, _]) {
                    let mut uses_timestamp = false;
                    let mut has_decay_calculation = false;
                    let mut has_block_based_decay = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for TIMESTAMP usage in decay calculation
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 { // TIMESTAMP
                                uses_timestamp = true;
                                // Check if followed by SUB (time difference) and DIV/MUL (decay calculation)
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x03 && // SUB
                                       (k + 2 < self.bytecode.len() && 
                                        (self.bytecode[k + 2] == 0x04 || self.bytecode[k + 2] == 0x02)) { // DIV or MUL
                                        has_decay_calculation = true;
                                    }
                                }
                            }
                        }
                        // Check for block-based decay (using NUMBER instead of TIMESTAMP)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x43 { // NUMBER
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x03 && // SUB
                                       (k + 2 < self.bytecode.len() && 
                                        (self.bytecode[k + 2] == 0x04 || self.bytecode[k + 2] == 0x02)) { // DIV or MUL
                                        has_block_based_decay = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Vulnerable if uses timestamp for decay without block-based alternative
                    if uses_timestamp && has_decay_calculation && !has_block_based_decay {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
