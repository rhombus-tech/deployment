use crate::bytecode::SecurityFinding;

pub struct DaoProposalSpammingDetector {
    bytecode: Vec<u8>,
}

impl DaoProposalSpammingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_unlimited_proposal_creation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "DAO allows unlimited proposal creation without rate limiting at PC {}. \
                    Attackers can spam proposals to disrupt governance.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_low_proposal_threshold() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Proposal creation threshold too low or missing at PC {}. \
                    Enables low-cost proposal spam attacks.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_missing_spam_protection() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "No spam protection mechanisms for proposal creation at PC {}. \
                    Missing cooldowns, fees, or reputation requirements.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_unlimited_proposal_creation(&self) -> Option<usize> {
        // Look for propose functions without rate limiting
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // propose, createProposal selectors
                if matches!(selector, [0xda, 0x95, 0x69, 0x1a] | [0x7c, 0x4d, _, _]) {
                    let mut has_rate_limit = false;
                    let mut has_proposal_cap = false;
                    let mut creates_proposal = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for rate limiting (time-based or count-based)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 { // TIMESTAMP
                                // Check if comparing against last proposal time
                                for k in j..j + 8 {
                                    if self.bytecode[k] == 0x54 && // SLOAD (last proposal time)
                                       k + 3 < self.bytecode.len() &&
                                       (self.bytecode[k + 3] == 0x10 || self.bytecode[k + 3] == 0x11) { // LT or GT
                                        has_rate_limit = true;
                                    }
                                }
                            }
                        }
                        // Check for active proposal count limit
                        if j + 10 < self.bytecode.len() {
                            let mut loads_proposal_count = false;
                            let mut compares_limit = false;
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x54 { // SLOAD (active proposal count)
                                    loads_proposal_count = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    compares_limit = true;
                                }
                            }
                            if loads_proposal_count && compares_limit {
                                has_proposal_cap = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE (creating new proposal)
                            creates_proposal = true;
                        }
                    }
                    
                    if creates_proposal && !has_rate_limit && !has_proposal_cap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_low_proposal_threshold(&self) -> Option<usize> {
        // Look for propose functions with insufficient token requirements
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // propose selector
                if matches!(selector, [0xda, 0x95, 0x69, 0x1a]) {
                    let mut has_threshold_check = false;
                    let mut threshold_appears_low = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for voting power/balance threshold
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD (user balance or voting power)
                                // Check if compared against threshold
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                        has_threshold_check = true;
                                        // Check if threshold constant is very low
                                        for m in j..k {
                                            if self.bytecode[m] == 0x60 || self.bytecode[m] == 0x61 { // PUSH1 or PUSH2
                                                // Low thresholds (< 1000 tokens worth considering low)
                                                if m + 1 < self.bytecode.len() {
                                                    let value = self.bytecode[m + 1] as usize;
                                                    if value < 10 { // Very low threshold
                                                        threshold_appears_low = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if !has_threshold_check || threshold_appears_low {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_missing_spam_protection(&self) -> Option<usize> {
        // Look for propose functions without comprehensive spam protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // propose, createProposal selectors
                if matches!(selector, [0xda, 0x95, 0x69, 0x1a] | [0x7c, 0x4d, _, _]) {
                    let mut has_cooldown = false;
                    let mut has_creation_fee = false;
                    let mut has_reputation_check = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for cooldown period
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_cooldown = true;
                            }
                        }
                        // Check for proposal fee (ETH or token payment)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x34 || // CALLVALUE (ETH fee)
                               self.bytecode[j] == 0xf1 { // CALL (token transfer for fee)
                                has_creation_fee = true;
                            }
                        }
                        // Check for reputation/voting power requirements
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getVotes, balanceOf, reputation selectors
                            if matches!(sub_selector, [0x95, 0x67, 0xb7, 0xf3] | [0x70, 0xa0, 0x82, 0x31] | [0xa2, 0x3f, _, _]) {
                                has_reputation_check = true;
                            }
                        }
                    }
                    
                    // Need at least two protection mechanisms
                    let protection_count = [has_cooldown, has_creation_fee, has_reputation_check]
                        .iter()
                        .filter(|&&x| x)
                        .count();
                    
                    if protection_count < 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
