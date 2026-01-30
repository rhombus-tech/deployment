use crate::bytecode::SecurityFinding;

pub struct SyntheticAssetCollateralDetector {
    bytecode: Vec<u8>,
}

impl SyntheticAssetCollateralDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_undercollateralization() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Synthetic asset can be minted with insufficient collateral at PC {}. \
                    Missing or weak collateralization ratio enforcement enables unbacked minting.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_collateral_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Collateral valuation relies on manipulable oracle at PC {}. \
                    Single oracle can be attacked to mint synthetics with inflated collateral value.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_liquidation_frontrunning() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Liquidation mechanism vulnerable to frontrunning at PC {}. \
                    Liquidators can manipulate prices to trigger unfair liquidations.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        findings
    }

    fn detect_undercollateralization(&self) -> Option<usize> {
        // Look for mint functions without proper collateral ratio checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // mint, mintSynth, openPosition selectors
                if matches!(selector, [0x40, 0xc1, 0x0f, 0x19] | [0x7a, 0x4e, _, _] | [0x8c, 0x5f, _, _]) {
                    let mut has_ratio_check = false;
                    let mut has_min_collateral = false;
                    let mut mints_tokens = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for collateralization ratio calculation and enforcement
                        if j + 15 < self.bytecode.len() {
                            let mut loads_collateral = false;
                            let mut loads_debt = false;
                            let mut calculates_ratio = false;
                            let mut enforces_minimum = false;
                            
                            for k in j..j + 15 {
                                if self.bytecode[k] == 0x54 { // SLOAD
                                    // Could be loading collateral or debt
                                    if k > j {
                                        loads_collateral = true;
                                    } else {
                                        loads_debt = true;
                                    }
                                }
                                if self.bytecode[k] == 0x04 { // DIV (ratio calculation)
                                    calculates_ratio = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    enforces_minimum = true;
                                }
                            }
                            
                            if loads_collateral && loads_debt && calculates_ratio && enforces_minimum {
                                has_ratio_check = true;
                            }
                        }
                        // Check for minimum collateral requirement
                        if j + 8 < self.bytecode.len() {
                            let mut compares_collateral = false;
                            let mut has_minimum_constant = false;
                            
                            for k in j..j + 8 {
                                if self.bytecode[k] == 0x60 || self.bytecode[k] == 0x61 { // PUSH1 or PUSH2
                                    has_minimum_constant = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    compares_collateral = true;
                                }
                            }
                            
                            if has_minimum_constant && compares_collateral {
                                has_min_collateral = true;
                            }
                        }
                        // Check if actually minting tokens
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // _mint internal function selector
                            if matches!(sub_selector, [0x40, 0xc1, _, _]) {
                                mints_tokens = true;
                            }
                        }
                    }
                    
                    if mints_tokens && !has_ratio_check && !has_min_collateral {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_collateral_oracle_manipulation(&self) -> Option<usize> {
        // Look for collateral valuation relying on single oracle
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getCollateralValue, calculateCollateral, valueCollateral selectors
                if matches!(selector, [0x6a, 0x3e, _, _] | [0x7c, 0x4f, _, _] | [0x8e, 0x6d, _, _]) {
                    let mut has_single_oracle = false;
                    let mut has_multiple_oracles = false;
                    let mut has_twap = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for single oracle call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // latestAnswer, getPrice (Chainlink-style)
                            if matches!(sub_selector, [0x50, 0xd2, 0x5b, 0xcd] | [0x98, 0xd5, 0xfd, 0xca]) {
                                has_single_oracle = true;
                            }
                        }
                        // Check for multiple oracle aggregation
                        if j + 30 < self.bytecode.len() {
                            let mut oracle_call_count = 0;
                            for k in j..j + 30 {
                                if self.bytecode[k] == 0xfa || self.bytecode[k] == 0xf1 { // STATICCALL or CALL
                                    oracle_call_count += 1;
                                }
                            }
                            if oracle_call_count >= 2 {
                                has_multiple_oracles = true;
                            }
                        }
                        // Check for TWAP calculation (time-weighted averaging)
                        if j + 12 < self.bytecode.len() {
                            let mut has_timestamp_diff = false;
                            let mut has_price_accumulation = false;
                            
                            for k in j..j + 12 {
                                if self.bytecode[k] == 0x42 { // TIMESTAMP
                                    if k + 2 < self.bytecode.len() && self.bytecode[k + 2] == 0x03 { // SUB
                                        has_timestamp_diff = true;
                                    }
                                }
                                if self.bytecode[k] == 0x02 || self.bytecode[k] == 0x04 { // MUL or DIV
                                    has_price_accumulation = true;
                                }
                            }
                            
                            if has_timestamp_diff && has_price_accumulation {
                                has_twap = true;
                            }
                        }
                    }
                    
                    if has_single_oracle && !has_multiple_oracles && !has_twap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_liquidation_frontrunning(&self) -> Option<usize> {
        // Look for liquidation functions without frontrunning protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // liquidate, liquidatePosition selectors
                if matches!(selector, [0x96, 0xcd, 0x46, 0x93] | [0x7c, 0x4d, _, _]) {
                    let mut has_twap_price = false;
                    let mut has_delay_mechanism = false;
                    let mut has_dutch_auction = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for TWAP price usage
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getTWAP, getTimeWeightedPrice selectors
                            if matches!(sub_selector, [0xa1, 0x2f, _, _] | [0xb3, 0x4d, _, _]) {
                                has_twap_price = true;
                            }
                        }
                        // Check for liquidation delay (grace period)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (liquidation trigger time)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x01 && // ADD (adding delay)
                               (self.bytecode[j + 6] == 0x10 || self.bytecode[j + 6] == 0x11) { // LT or GT
                                has_delay_mechanism = true;
                            }
                        }
                        // Check for Dutch auction liquidation (declining penalty)
                        if j + 10 < self.bytecode.len() {
                            let mut calculates_time_factor = false;
                            let mut applies_to_penalty = false;
                            
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x42 { // TIMESTAMP
                                    calculates_time_factor = true;
                                }
                                if self.bytecode[k] == 0x02 && calculates_time_factor { // MUL (time-based penalty)
                                    applies_to_penalty = true;
                                }
                            }
                            
                            if calculates_time_factor && applies_to_penalty {
                                has_dutch_auction = true;
                            }
                        }
                    }
                    
                    if !has_twap_price && !has_delay_mechanism && !has_dutch_auction {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
