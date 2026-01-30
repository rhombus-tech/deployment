use crate::bytecode::SecurityFinding;

pub struct EndorsementBriberyDetector {
    bytecode: Vec<u8>,
}

impl EndorsementBriberyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_bribery_incentive() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Endorsement system allows financial incentives that enable bribery at PC {}. \
                    Users can be paid to endorse malicious actors.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_self_endorsement() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "System allows self-endorsement without penalties at PC {}. \
                    Reputation can be artificially inflated.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_endorsement_wash_trading() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Mutual endorsement without cycle detection enables wash trading at PC {}. \
                    Collusive actors can inflate each other's reputation.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_bribery_incentive(&self) -> Option<usize> {
        // Look for endorsement functions that transfer value/rewards
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // endorse, vouch, attest selectors
                if matches!(selector, [0x4e, 0x7a, _, _] | [0x5f, 0x8b, _, _] | [0x6d, 0x9c, _, _]) {
                    let mut has_value_transfer = false;
                    let mut has_token_transfer = false;
                    let mut has_reward_mint = false;
                    let mut has_anti_bribery = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for ETH transfer (CALL with value)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0xf1 { // CALL
                                // Check if value parameter is non-zero
                                for k in j.saturating_sub(15)..j {
                                    if self.bytecode[k] == 0x60 && k + 1 < self.bytecode.len() {
                                        if self.bytecode[k + 1] != 0x00 { // Non-zero value
                                            has_value_transfer = true;
                                        }
                                    }
                                }
                            }
                        }
                        // Check for token transfer call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // transfer, transferFrom selectors
                            if matches!(sub_selector, [0xa9, 0x05, 0x9c, 0xbb] | [0x23, 0xb8, 0x72, 0xdd]) {
                                has_token_transfer = true;
                            }
                            // mint selector (reward tokens)
                            if matches!(sub_selector, [0x40, 0xc1, 0x0f, 0x19]) {
                                has_reward_mint = true;
                            }
                        }
                        // Check for anti-bribery mechanisms (time lock, stake requirement)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 3 < self.bytecode.len() &&
                               (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) { // LT or GT (timelock)
                                has_anti_bribery = true;
                            }
                        }
                    }
                    
                    if (has_value_transfer || has_token_transfer || has_reward_mint) && !has_anti_bribery {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_self_endorsement(&self) -> Option<usize> {
        // Look for endorsement functions without self-endorsement prevention
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // endorse, vouch, rate selectors
                if matches!(selector, [0x4e, 0x7a, _, _] | [0x5f, 0x8b, _, _] | [0x7c, 0x3d, _, _]) {
                    let mut has_self_check = false;
                    let mut stores_endorsement = false;
                    
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        // Check for self-endorsement prevention (CALLER != target)
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 { // CALLER
                                // Look for comparison with target address
                                for k in j..j + 5 {
                                    if self.bytecode[k] == 0x14 { // EQ
                                        if k + 1 < self.bytecode.len() && self.bytecode[k + 1] == 0x15 { // ISZERO (not equal)
                                            has_self_check = true;
                                        }
                                    }
                                }
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE (storing endorsement)
                            stores_endorsement = true;
                        }
                    }
                    
                    if stores_endorsement && !has_self_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_endorsement_wash_trading(&self) -> Option<usize> {
        // Look for mutual endorsement without cycle/reciprocity detection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // endorse, vouch selectors
                if matches!(selector, [0x4e, 0x7a, _, _] | [0x5f, 0x8b, _, _]) {
                    let mut has_reciprocity_check = false;
                    let mut has_cooldown = false;
                    let mut stores_endorsement = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for reciprocal endorsement detection (checking if target endorsed caller)
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                // Check if loading reverse endorsement mapping
                                let mut loads_caller = false;
                                let mut loads_target = false;
                                for k in j.saturating_sub(8)..j {
                                    if self.bytecode[k] == 0x33 { // CALLER
                                        loads_caller = true;
                                    }
                                }
                                if loads_caller {
                                    // Check if compared
                                    for k in j..j + 5 {
                                        if self.bytecode[k] == 0x14 || self.bytecode[k] == 0x15 { // EQ or ISZERO
                                            has_reciprocity_check = true;
                                        }
                                    }
                                }
                            }
                        }
                        // Check for cooldown period (timestamp-based rate limiting)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (last endorsement time)
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_cooldown = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE
                            stores_endorsement = true;
                        }
                    }
                    
                    if stores_endorsement && !has_reciprocity_check && !has_cooldown {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
