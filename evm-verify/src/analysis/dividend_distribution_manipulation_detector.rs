use crate::bytecode::SecurityFinding;

pub struct DividendDistributionManipulationDetector {
    bytecode: Vec<u8>,
}

impl DividendDistributionManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_snapshot_gaming() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Dividend snapshot timing predictable at PC {}. \
                    Attackers can front-run snapshot to manipulate distribution shares.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_whale_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Dividend distribution vulnerable to whale manipulation at PC {}. \
                    Large holders can flash-acquire shares right before distribution.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_distribution_dilution() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Dividend distribution lacks pro-rata protection at PC {}. \
                    Distribution can be diluted through token minting before payout.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_snapshot_gaming(&self) -> Option<usize> {
        // Look for predictable snapshot timing in dividend distribution
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // snapshot, takeSnapshot, captureBalances selectors
                if matches!(selector, [0xf2, 0x4d, _, _] | [0xe3, 0x5c, _, _] | [0xd1, 0x6b, _, _]) {
                    let mut has_unpredictable_timing = false;
                    let mut uses_blockhash = false;
                    let mut has_delay_mechanism = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for randomness source (PREVRANDAO or blockhash)
                        if self.bytecode[j] == 0x44 { // PREVRANDAO
                            has_unpredictable_timing = true;
                        }
                        if self.bytecode[j] == 0x40 { // BLOCKHASH
                            uses_blockhash = true;
                        }
                        // Check for time delay or commit-reveal
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x01 && // ADD (adding delay)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x10 { // LT (checking time passed)
                                has_delay_mechanism = true;
                            }
                        }
                    }
                    
                    // Flag if snapshot timing is predictable
                    if !has_unpredictable_timing && !uses_blockhash && !has_delay_mechanism {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_whale_manipulation(&self) -> Option<usize> {
        // Look for dividend distribution without minimum holding period
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // distributeDividends, claimDividends, processDividends selectors
                if matches!(selector, [0xa1, 0x2e, _, _] | [0xb2, 0x3f, _, _] | [0xc3, 0x4c, _, _]) {
                    let mut has_holding_period_check = false;
                    let mut has_snapshot_comparison = false;
                    let mut loads_historical_balance = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for holding period validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (last transfer time)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x42 && // TIMESTAMP
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x03 && // SUB
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x10 { // LT (checking minimum hold time)
                                has_holding_period_check = true;
                            }
                        }
                        // Check for snapshot balance comparison
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (snapshot balance)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (current balance)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x14 { // EQ (comparing balances)
                                has_snapshot_comparison = true;
                            }
                        }
                        // Check if loading historical balance data
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256 (historical mapping)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x54 { // SLOAD
                                loads_historical_balance = true;
                            }
                        }
                    }
                    
                    if !has_holding_period_check && !has_snapshot_comparison {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_distribution_dilution(&self) -> Option<usize> {
        // Look for dividend calculation without supply lock
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // calculateDividends, computeShares selectors
                if matches!(selector, [0xd2, 0x3e, _, _] | [0xe1, 0x4f, _, _]) {
                    let mut uses_snapshot_supply = false;
                    let mut locks_total_supply = false;
                    let mut calculates_distribution = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check if using snapshot total supply
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (snapshot supply)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x04 { // DIV (calculating share)
                                uses_snapshot_supply = true;
                            }
                        }
                        // Check if loading total supply at distribution time
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // totalSupply selector
                            if matches!(sub_selector, [0x18, 0x16, 0x0d, 0xdd]) {
                                calculates_distribution = true;
                            }
                        }
                        // Check for supply lock during distribution
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x55 && // SSTORE (storing locked supply)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 { // SLOAD (loading current supply)
                                locks_total_supply = true;
                            }
                        }
                    }
                    
                    if calculates_distribution && !uses_snapshot_supply && !locks_total_supply {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
