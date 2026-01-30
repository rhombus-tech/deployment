use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetapoolVirtualPriceVulnerability {
    pub location: usize,
    pub manipulation_type: VirtualPriceManipulationType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VirtualPriceManipulationType {
    VirtualPriceInflation,           // Virtual price artificially inflated
    BasePoolManipulation,            // Base pool price manipulated
    ImbalancedDeposit,               // Deposit imbalance attack
    WithdrawOneCoinExploit,          // withdraw_one_coin manipulation
    DonationAttack,                  // Direct token donation
    CachedPriceStale,                // Cached price not updated
}

pub struct MetapoolVirtualPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl MetapoolVirtualPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MetapoolVirtualPriceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_virtual_price_inflation() {
            vulnerabilities.push(MetapoolVirtualPriceVulnerability {
                location: loc,
                manipulation_type: VirtualPriceManipulationType::VirtualPriceInflation,
                severity: "Critical".to_string(),
                description: "Metapool virtual price manipulable via imbalanced operations. Saddle Finance \
                             $11M exploit: attacker inflated virtual price through imbalanced swaps to drain \
                             pool. MUST validate virtual price changes.".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_base_pool_manipulation() {
            vulnerabilities.push(MetapoolVirtualPriceVulnerability {
                location: loc,
                manipulation_type: VirtualPriceManipulationType::BasePoolManipulation,
                severity: "Critical".to_string(),
                description: "Base pool price used without validation. Attacker can manipulate underlying \
                             base pool to affect metapool virtual price calculation.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_imbalanced_deposit() {
            vulnerabilities.push(MetapoolVirtualPriceVulnerability {
                location: loc,
                manipulation_type: VirtualPriceManipulationType::ImbalancedDeposit,
                severity: "High".to_string(),
                description: "Imbalanced deposit can inflate virtual price. No slippage protection or \
                             imbalance limits allow depositing heavily skewed ratios.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_withdraw_one_coin_exploit() {
            vulnerabilities.push(MetapoolVirtualPriceVulnerability {
                location: loc,
                manipulation_type: VirtualPriceManipulationType::WithdrawOneCoinExploit,
                severity: "High".to_string(),
                description: "withdraw_one_coin vulnerable to virtual price manipulation. Single-sided \
                             withdrawal affects price without proper recalculation.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_donation_attack() {
            vulnerabilities.push(MetapoolVirtualPriceVulnerability {
                location: loc,
                manipulation_type: VirtualPriceManipulationType::DonationAttack,
                severity: "High".to_string(),
                description: "Direct token donation can inflate virtual price. Pool balance read directly \
                             without accounting for legitimate LP shares.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_cached_price_stale() {
            vulnerabilities.push(MetapoolVirtualPriceVulnerability {
                location: loc,
                manipulation_type: VirtualPriceManipulationType::CachedPriceStale,
                severity: "Medium".to_string(),
                description: "Cached virtual price not updated frequently. Stale cache allows exploiting \
                             price discrepancies between cached and actual values.".to_string(),
                confidence: 0.83,
            });
        }

        vulnerabilities
    }

    fn detect_virtual_price_inflation(&self) -> Option<usize> {
        // get_virtual_price without proper validation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // get_virtual_price (0xbb7b8b80)
                if selector == 0xbb7b8b80 {
                    // Check for balance/totalSupply validation
                    let mut has_validation = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 { // DIV
                            // Check if bounded
                            for k in j..std::cmp::min(j + 15, self.bytecode.len()) {
                                if matches!(self.bytecode[k], 0x10 | 0x11) {
                                    has_validation = true;
                                    break;
                                }
                            }
                            if has_validation {
                                break;
                            }
                        }
                    }
                    if !has_validation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_base_pool_manipulation(&self) -> Option<usize> {
        // Base pool price read without validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xfa { // STATICCALL to base pool
                // Check if result validated
                let mut has_sanity_check = false;
                for j in i..std::cmp::min(i + 30, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) {
                        has_sanity_check = true;
                        break;
                    }
                }
                if !has_sanity_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_imbalanced_deposit(&self) -> Option<usize> {
        // add_liquidity without balance checks
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // add_liquidity (0x0b4c7e4d)
                if selector == 0x0b4c7e4d {
                    // Check for imbalance limits
                    let mut has_imbalance_check = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 { // DIV (ratio check)
                            has_imbalance_check = true;
                            break;
                        }
                    }
                    if !has_imbalance_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_withdraw_one_coin_exploit(&self) -> Option<usize> {
        // remove_liquidity_one_coin without virtual price update
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // remove_liquidity_one_coin (0x1a4d01d2)
                if selector == 0x1a4d01d2 {
                    // Check for virtual price recalculation (SSTORE)
                    let mut has_price_update = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (updating cached price)
                            has_price_update = true;
                            break;
                        }
                    }
                    if !has_price_update {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_donation_attack(&self) -> Option<usize> {
        // BALANCE read in virtual price calculation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x31 { // BALANCE
                // Check if used in division (virtual price calc)
                for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        // Virtual price should use internal accounting, not raw balance
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cached_price_stale(&self) -> Option<usize> {
        // Cached price SLOAD without staleness check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (cached price)
                // Check if timestamp validated
                let mut has_staleness_check = false;
                for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        has_staleness_check = true;
                        break;
                    }
                }
                
                // If this looks like price storage
                let is_price_storage = i > 20 && {
                    let mut found = false;
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0xbb7b8b80 { // get_virtual_price
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if is_price_storage && !has_staleness_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
