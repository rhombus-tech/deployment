use crate::bytecode::SecurityFinding;

pub struct MechanismDesignFailureDetector {
    bytecode: Vec<u8>,
}

impl MechanismDesignFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_incentive_incompatibility() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Mechanism design violates incentive compatibility at PC {}. \
                    Rational actors can profit by deviating from honest behavior.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_sybil_resistance_failure() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Mechanism vulnerable to Sybil attacks at PC {}. \
                    Multiple fake identities can game the incentive structure.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_collusion_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Mechanism design enables profitable collusion at PC {}. \
                    Coordinated actors can extract more value than honest participants.",
                    pc
                ),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_incentive_incompatibility(&self) -> Option<usize> {
        // Look for reward/penalty mechanisms that don't align with honest behavior
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // distributeRewards, calculatePayoff, allocate selectors
                if matches!(selector, [0xa1, 0x3e, _, _] | [0xb2, 0x4f, _, _] | [0xc3, 0x5d, _, _]) {
                    let mut rewards_based_on_outcome = false;
                    let mut validates_honest_reporting = false;
                    let mut penalizes_deviation = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check if rewards depend on reported outcome
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (report)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x02 && // MUL (reward calculation)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x55 { // SSTORE
                                rewards_based_on_outcome = true;
                            }
                        }
                        
                        // Check for truthful reporting validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (ground truth)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x35 && // CALLDATALOAD (report)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                validates_honest_reporting = true;
                            }
                        }
                        
                        // Check for deviation penalties
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (expected behavior)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x14 && // EQ
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (if deviated)
                                penalizes_deviation = true;
                            }
                        }
                    }
                    
                    if rewards_based_on_outcome && !validates_honest_reporting && !penalizes_deviation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_sybil_resistance_failure(&self) -> Option<usize> {
        // Look for mechanisms vulnerable to multiple identity attacks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // register, participate, vote selectors
                if matches!(selector, [0xa2, 0x3e, _, _] | [0xb3, 0x4f, _, _] | [0xc4, 0x5d, _, _]) {
                    let mut has_identity_cost = false;
                    let mut validates_uniqueness = false;
                    let mut requires_stake = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for registration cost
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x34 && // CALLVALUE
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (minimum payment)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO
                                has_identity_cost = true;
                            }
                        }
                        
                        // Check for uniqueness validation (proof of personhood)
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (registered)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (not already registered)
                                validates_uniqueness = true;
                            }
                        }
                        
                        // Check for stake requirement
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (stake amount)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x55 { // SSTORE (locking stake)
                                requires_stake = true;
                            }
                        }
                    }
                    
                    if !has_identity_cost && !validates_uniqueness && !requires_stake {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_collusion_vulnerability(&self) -> Option<usize> {
        // Look for auction/allocation mechanisms vulnerable to collusion
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // bid, offer, propose selectors
                if matches!(selector, [0xa3, 0x3e, _, _] | [0xb4, 0x4f, _, _] | [0xc5, 0x5d, _, _]) {
                    let mut reveals_other_bids = false;
                    let mut uses_commit_reveal = false;
                    let mut randomizes_winner = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if other participants' bids are visible
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (other bids)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0xf3 { // RETURN (exposing)
                                reveals_other_bids = true;
                            }
                        }
                        
                        // Check for commit-reveal scheme
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256 (commit)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x55 && // SSTORE
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x54 { // SLOAD (reveal later)
                                uses_commit_reveal = true;
                            }
                        }
                        
                        // Check for randomized selection (VRF)
                        if self.bytecode[j] == 0x44 { // PREVRANDAO
                            randomizes_winner = true;
                        }
                    }
                    
                    if reveals_other_bids && !uses_commit_reveal && !randomizes_winner {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
