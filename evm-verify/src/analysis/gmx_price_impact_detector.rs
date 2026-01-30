use crate::bytecode::SecurityFinding;

pub struct GmxPriceImpactDetector {
    bytecode: Vec<u8>,
}

impl GmxPriceImpactDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_price_impact_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "GMX price impact calculation vulnerable to manipulation at PC {}. \
                    Attacker can artificially inflate price impact to extract value from traders.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_position_size_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "GMX position sizing lacks proper price impact limits at PC {}. \
                    Large positions can move market significantly without adequate protection.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_oracle_price_lag() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "GMX price oracle has lag vulnerability at PC {}. \
                    Stale prices can be exploited for profitable trades against the protocol.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_price_impact_manipulation(&self) -> Option<usize> {
        // Look for price impact calculation without proper safeguards
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // increasePosition, decreasePosition, swap selectors
                if matches!(selector, [0xf2, 0x5e, _, _] | [0xe1, 0x4f, _, _] | [0x38, 0xed, 0x17, 0x39]) {
                    let mut calculates_price_impact = false;
                    let mut has_impact_cap = false;
                    let mut validates_liquidity = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for price impact calculation (division)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (pool reserves)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x04 { // DIV (calculating impact)
                                calculates_price_impact = true;
                            }
                        }
                        // Check for maximum impact cap
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x10 && // LT (comparing to cap)
                               j + 2 < self.bytecode.len() &&
                               self.bytecode[j + 1] == 0x15 { // ISZERO (require check)
                                has_impact_cap = true;
                            }
                        }
                        // Check for liquidity depth validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (total liquidity)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x02 && // MUL (percentage calc)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x10 { // LT (checking within bounds)
                                validates_liquidity = true;
                            }
                        }
                    }
                    
                    if calculates_price_impact && (!has_impact_cap || !validates_liquidity) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_position_size_exploit(&self) -> Option<usize> {
        // Look for position increases without size/leverage limits
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // increasePosition, leverage selectors
                if matches!(selector, [0xf2, 0x5e, _, _] | [0xd3, 0x4c, _, _]) {
                    let mut has_size_limit = false;
                    let mut has_leverage_cap = false;
                    let mut checks_open_interest = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for position size limit
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (size)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (comparing to max)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (require)
                                has_size_limit = true;
                            }
                        }
                        // Check for leverage cap
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x04 && // DIV (calculating leverage)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x10 { // LT (max leverage check)
                                has_leverage_cap = true;
                            }
                        }
                        // Check for open interest validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (open interest)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x01 && // ADD (adding position)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (checking limit)
                                checks_open_interest = true;
                            }
                        }
                    }
                    
                    if !has_size_limit || !has_leverage_cap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_oracle_price_lag(&self) -> Option<usize> {
        // Look for price oracle usage without freshness checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getPrice, updatePrice, executeTrade selectors
                if matches!(selector, [0xa1, 0x3e, _, _] | [0xb2, 0x4f, _, _] | [0xc3, 0x5d, _, _]) {
                    let mut loads_oracle_price = false;
                    let mut checks_timestamp = false;
                    let mut validates_freshness = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for oracle price load
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // Chainlink latestRoundData selector
                            if matches!(sub_selector, [0xfe, 0xaf, 0x96, 0x8c]) {
                                loads_oracle_price = true;
                            }
                        }
                        // Check for timestamp comparison
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x03 && // SUB (time difference)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (checking staleness)
                                checks_timestamp = true;
                            }
                        }
                        // Check for price deviation validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (last price)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x03 && // SUB (price diff)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x10 { // LT (max deviation)
                                validates_freshness = true;
                            }
                        }
                    }
                    
                    if loads_oracle_price && !checks_timestamp && !validates_freshness {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
