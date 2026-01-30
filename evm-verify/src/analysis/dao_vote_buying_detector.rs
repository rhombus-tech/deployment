use crate::bytecode::SecurityFinding;

pub struct DaoVoteBuyingDetector {
    bytecode: Vec<u8>,
}

impl DaoVoteBuyingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_transferable_voting_power() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Voting power can be transferred during active proposals at PC {}, enabling vote buying. \
                    Attackers can purchase voting power to manipulate governance outcomes.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_flash_loan_voting() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Governance allows flash loan-based voting at PC {}. \
                    Temporary token borrowing can manipulate vote outcomes.",
                    pc
                ),
                pc,
                confidence: 0.94,
            });
        }

        if let Some(pc) = self.detect_vote_delegation_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Vote delegation can be exploited for vote concentration at PC {}. \
                    Missing checks allow malicious delegation patterns.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_transferable_voting_power(&self) -> Option<usize> {
        // Look for voting functions that don't snapshot at proposal creation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // castVote, vote, submitVote selectors
                if matches!(selector, [0x56, 0x78, 0x1a, 0xbd] | [0x15, 0x37, 0x3e, 0x3d] | [0x7c, 0x4d, _, _]) {
                    let mut uses_snapshot = false;
                    let mut uses_current_balance = false;
                    let mut has_transfer_lock = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for snapshot lookup (historical balance query)
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getPastVotes, balanceOfAt selectors
                            if matches!(sub_selector, [0x3a, 0x46, 0xb1, 0xa8] | [0x4e, 0xe2, 0xcd, 0x7e]) {
                                uses_snapshot = true;
                            }
                            // balanceOf (current balance - vulnerable!)
                            if matches!(sub_selector, [0x70, 0xa0, 0x82, 0x31]) {
                                uses_current_balance = true;
                            }
                        }
                        // Check for transfer lock during voting period
                        if j + 10 < self.bytecode.len() {
                            let mut checks_active_vote = false;
                            let mut prevents_transfer = false;
                            for k in j..j + 10 {
                                // Check if loading active proposals mapping
                                if self.bytecode[k] == 0x54 { // SLOAD
                                    checks_active_vote = true;
                                }
                                // Check if transfer reverts during active vote
                                if self.bytecode[k] == 0xfd { // REVERT
                                    prevents_transfer = true;
                                }
                            }
                            if checks_active_vote && prevents_transfer {
                                has_transfer_lock = true;
                            }
                        }
                    }
                    
                    if uses_current_balance && !uses_snapshot && !has_transfer_lock {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_flash_loan_voting(&self) -> Option<usize> {
        // Look for voting without block delay requirements
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // castVote, vote selectors
                if matches!(selector, [0x56, 0x78, 0x1a, 0xbd] | [0x15, 0x37, 0x3e, 0x3d]) {
                    let mut has_block_delay = false;
                    let mut has_snapshot_validation = false;
                    let mut requires_minimum_holding = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for block number validation (preventing same-block voting)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x43 && // NUMBER (block number)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (proposal creation block)
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_block_delay = true;
                            }
                        }
                        // Check for snapshot block validation
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getPastVotes with block parameter
                            if matches!(sub_selector, [0x3a, 0x46, 0xb1, 0xa8]) {
                                has_snapshot_validation = true;
                            }
                        }
                        // Check for minimum holding period (timestamp comparison)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (token acquisition time)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x01 && // ADD (adding delay)
                               (self.bytecode[j + 6] == 0x10 || self.bytecode[j + 6] == 0x11) { // LT or GT
                                requires_minimum_holding = true;
                            }
                        }
                    }
                    
                    if !has_block_delay && !has_snapshot_validation && !requires_minimum_holding {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_vote_delegation_exploit(&self) -> Option<usize> {
        // Look for delegation functions without proper safeguards
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // delegate, delegateBySig selectors
                if matches!(selector, [0x5c, 0x19, 0xa9, 0x5c] | [0xc3, 0xcd, 0xa5, 0x20]) {
                    let mut has_cycle_check = false;
                    let mut has_delegation_limit = false;
                    let mut has_cooldown = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for delegation cycle detection (A→B→A)
                        if j + 15 < self.bytecode.len() {
                            let mut recursive_checks = 0;
                            for k in j..j + 15 {
                                if self.bytecode[k] == 0x54 { // SLOAD (checking delegation chain)
                                    recursive_checks += 1;
                                }
                            }
                            if recursive_checks >= 2 {
                                has_cycle_check = true;
                            }
                        }
                        // Check for delegation depth limit
                        if j + 8 < self.bytecode.len() {
                            let mut has_counter = false;
                            let mut has_max_check = false;
                            for k in j..j + 8 {
                                if self.bytecode[k] == 0x01 { // ADD (counter increment)
                                    has_counter = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    has_max_check = true;
                                }
                            }
                            if has_counter && has_max_check {
                                has_delegation_limit = true;
                            }
                        }
                        // Check for delegation cooldown period
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (last delegation time)
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_cooldown = true;
                            }
                        }
                    }
                    
                    if !has_cycle_check && !has_delegation_limit && !has_cooldown {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
