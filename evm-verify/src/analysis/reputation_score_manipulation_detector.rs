use crate::bytecode::SecurityFinding;

pub struct ReputationScoreManipulationDetector {
    bytecode: Vec<u8>,
}

impl ReputationScoreManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_self_boosting() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Reputation system allows self-boosting without restrictions at PC {}. \
                    Users can artificially inflate their own reputation scores.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_sybil_attack_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Reputation system vulnerable to sybil attacks at PC {}. \
                    Missing unique identity verification allows creation of multiple accounts for score manipulation.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_score_overflow() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Reputation score calculation lacks overflow protection at PC {}. \
                    Score accumulation can overflow, wrapping to low values.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_admin_score_backdoor() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Admin can arbitrarily set reputation scores without constraints at PC {}. \
                    Centralized control undermines reputation integrity.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        findings
    }

    fn detect_self_boosting(&self) -> Option<usize> {
        // Look for reputation functions that allow CALLER to boost their own score
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // increaseReputation, upvote, endorse selectors
                if matches!(selector, [0x7c, 0x02, _, _] | [0xb5, 0x45, _, _] | [0xe1, 0x4e, _, _]) {
                    let mut caller_used = false;
                    let mut has_self_check = false;
                    
                    for j in i..i.saturating_add(40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 { // CALLER
                            caller_used = true;
                        }
                        // Check for protection against self-boosting (CALLER != target check)
                        if j + 3 < self.bytecode.len() && self.bytecode[j] == 0x14 { // EQ
                            if j + 2 < self.bytecode.len() && self.bytecode[j + 1] == 0x15 { // ISZERO (!=)
                                has_self_check = true;
                            }
                        }
                    }
                    
                    if caller_used && !has_self_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_sybil_attack_vulnerability(&self) -> Option<usize> {
        // Look for reputation functions without identity/uniqueness verification
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // register, createProfile, joinNetwork selectors
                if matches!(selector, [0x4a, 0x21, _, _] | [0x69, 0x87, _, _] | [0x2f, 0x4f, _, _]) {
                    let mut has_kycverification = false;
                    let mut has_uniqueness_check = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Look for external KYC/identity verification calls
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x63 {
                                let sub_selector = &self.bytecode[j + 1..j + 5];
                                // verifyIdentity, checkKYC, isUnique selectors
                                if matches!(sub_selector, [0xa5, 0x7e, _, _] | [0xb2, 0x9f, _, _] | [0xc8, 0x11, _, _]) {
                                    has_kycverification = true;
                                }
                            }
                        }
                        // Look for uniqueness storage checks (SLOAD checking existing address)
                        if j + 2 < self.bytecode.len() && self.bytecode[j] == 0x54 { // SLOAD
                            if self.bytecode[j + 1] == 0x15 { // ISZERO
                                has_uniqueness_check = true;
                            }
                        }
                    }
                    
                    if !has_kycverification && !has_uniqueness_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_score_overflow(&self) -> Option<usize> {
        // Look for reputation score updates without overflow checks
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // addReputation, increaseScore selectors
                if matches!(selector, [0x7c, 0x02, _, _] | [0x8a, 0x3d, _, _]) {
                    let mut has_add = false;
                    let mut has_overflow_check = false;
                    
                    for j in i..i.saturating_add(30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x01 { // ADD
                            has_add = true;
                        }
                        // Look for overflow checks (LT check after ADD, or SafeMath pattern)
                        if j + 2 < self.bytecode.len() && self.bytecode[j] == 0x10 { // LT
                            if self.bytecode[j + 1] == 0x15 { // ISZERO
                                has_overflow_check = true;
                            }
                        }
                    }
                    
                    if has_add && !has_overflow_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_admin_score_backdoor(&self) -> Option<usize> {
        // Look for admin functions that can arbitrarily set reputation scores
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // setReputation, overrideScore selectors
                if matches!(selector, [0x6d, 0x8e, _, _] | [0x9b, 0x2c, _, _]) {
                    let mut has_admin_check = false;
                    let mut has_bounds_check = false;
                    let mut has_sstore = false;
                    
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        // Check for admin/owner verification
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // onlyOwner patterns usually check msg.sender against owner slot
                            if matches!(sub_selector, [0x8d, 0xa5, _, _] | [0x70, 0xa0, _, _]) {
                                has_admin_check = true;
                            }
                        }
                        // Look for bounds/reasonableness checks on score value
                        if j + 1 < self.bytecode.len() && (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) {
                            // LT or GT (checking bounds)
                            has_bounds_check = true;
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE
                            has_sstore = true;
                        }
                    }
                    
                    // Admin backdoor if admin check exists but no bounds check (unlimited power)
                    if has_admin_check && !has_bounds_check && has_sstore {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
