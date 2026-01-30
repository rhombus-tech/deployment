use crate::bytecode::SecurityFinding;

pub struct SynthetixDebtPoolDetector {
    bytecode: Vec<u8>,
}

impl SynthetixDebtPoolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_debt_pool_frontrunning() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Synthetix debt pool snapshot vulnerable to frontrunning at PC {}. \
                    Attackers can manipulate debt shares by timing mints/burns around snapshots.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_debt_share_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Debt share calculation lacks atomic protection at PC {}. \
                    Debt ratio can be manipulated through flash loans and cross-synth trades.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_cross_asset_arbitrage() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Cross-synth arbitrage can shift debt pool ratios at PC {}. \
                    Oracle lag allows profitable trades that redistribute debt unfairly.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_debt_pool_frontrunning(&self) -> Option<usize> {
        // Look for debt snapshot operations without frontrunning protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // takeDebtSnapshot, updateDebt, rebalance selectors
                if matches!(selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0xf3, 0x5c, _, _]) {
                    let mut has_commit_reveal = false;
                    let mut has_time_delay = false;
                    let mut uses_vrf = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for commit-reveal mechanism
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256 (commit hash)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x55 && // SSTORE (storing commit)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x54 { // SLOAD (checking reveal)
                                has_commit_reveal = true;
                            }
                        }
                        // Check for time delay
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x01 && // ADD (adding delay)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (checking time passed)
                                has_time_delay = true;
                            }
                        }
                        // Check for VRF/randomness
                        if self.bytecode[j] == 0x44 { // PREVRANDAO
                            uses_vrf = true;
                        }
                    }
                    
                    if !has_commit_reveal && !has_time_delay && !uses_vrf {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_debt_share_manipulation(&self) -> Option<usize> {
        // Look for debt share calculation without reentrancy/flash loan protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // mint, burn, exchange selectors
                if matches!(selector, [0x40, 0xc1, 0x0f, 0x19] | [0x42, 0x96, 0x6c, 0x68] | [0xa1, 0x2e, _, _]) {
                    let mut updates_debt_ratio = false;
                    let mut has_reentrancy_guard = false;
                    let mut validates_flash_loan = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for debt ratio update
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (total debt)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x04 && // DIV (calculating ratio)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x55 { // SSTORE (updating)
                                updates_debt_ratio = true;
                            }
                        }
                        // Check for reentrancy guard
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (guard)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 && // ISZERO
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x55 { // SSTORE (setting guard)
                                has_reentrancy_guard = true;
                            }
                        }
                        // Check for flash loan detection
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (balance before)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x54 && // SLOAD (balance after)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x14 { // EQ (checking no net change)
                                validates_flash_loan = true;
                            }
                        }
                    }
                    
                    if updates_debt_ratio && !has_reentrancy_guard && !validates_flash_loan {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cross_asset_arbitrage(&self) -> Option<usize> {
        // Look for synth exchanges without oracle synchronization
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // exchange, swap selectors
                if matches!(selector, [0xa1, 0x2e, _, _] | [0x38, 0xed, 0x17, 0x39]) {
                    let mut uses_oracle = false;
                    let mut checks_oracle_freshness = false;
                    let mut validates_deviation = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for oracle call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // Chainlink latestRoundData
                            if matches!(sub_selector, [0xfe, 0xaf, 0x96, 0x8c]) {
                                uses_oracle = true;
                            }
                        }
                        // Check oracle timestamp validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x03 && // SUB
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (max age check)
                                checks_oracle_freshness = true;
                            }
                        }
                        // Check for price deviation limits
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (reference price)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x03 && // SUB (deviation)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x10 { // LT (max deviation)
                                validates_deviation = true;
                            }
                        }
                    }
                    
                    if uses_oracle && !checks_oracle_freshness && !validates_deviation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
