use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LpTokenDirectOraclePricingVulnerability {
    pub location: usize,
    pub pricing_type: LpOraclePricingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LpOraclePricingType {
    DirectSpotPriceUsage,            // Using spot price directly
    ReservesManipulation,            // Pool reserves manipulable
    MissingFairPriceFormula,         // Not using fair LP valuation
    SingleBlockPriceSnapshot,        // Single block price used
    NoTWAPIntegration,               // No time-weighted averaging
    FlashLoanPriceAttack,            // Vulnerable to flash loan
}

pub struct LpTokenDirectOraclePricingDetector {
    bytecode: Vec<u8>,
}

impl LpTokenDirectOraclePricingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LpTokenDirectOraclePricingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_direct_spot_price() {
            vulnerabilities.push(LpTokenDirectOraclePricingVulnerability {
                location: loc,
                pricing_type: LpOraclePricingType::DirectSpotPriceUsage,
                severity: "Critical".to_string(),
                description: "LP token valued using direct spot price. Deus Finance $13.4M exploit: attacker \
                             manipulated pool reserves to inflate LP value. MUST use fair price formula: \
                             2 * sqrt(reserve0 * reserve1) * sqrt(price0 * price1) / totalSupply".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_reserves_manipulation() {
            vulnerabilities.push(LpTokenDirectOraclePricingVulnerability {
                location: loc,
                pricing_type: LpOraclePricingType::ReservesManipulation,
                severity: "Critical".to_string(),
                description: "Pool reserves read directly without manipulation check. Flash loan can alter \
                             reserves to manipulate LP valuation in same transaction.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_missing_fair_price() {
            vulnerabilities.push(LpTokenDirectOraclePricingVulnerability {
                location: loc,
                pricing_type: LpOraclePricingType::MissingFairPriceFormula,
                severity: "Critical".to_string(),
                description: "LP token valuation not using fair price formula. Simple reserve ratio allows \
                             single-sided manipulation. Must use geometric mean formula.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_single_block_snapshot() {
            vulnerabilities.push(LpTokenDirectOraclePricingVulnerability {
                location: loc,
                pricing_type: LpOraclePricingType::SingleBlockPriceSnapshot,
                severity: "High".to_string(),
                description: "LP price taken from single block snapshot. Vulnerable to sandwich attacks and \
                             multi-block manipulation. Needs multi-block observation.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_no_twap() {
            vulnerabilities.push(LpTokenDirectOraclePricingVulnerability {
                location: loc,
                pricing_type: LpOraclePricingType::NoTWAPIntegration,
                severity: "High".to_string(),
                description: "LP pricing without TWAP integration. Spot reserves used without time averaging, \
                             enabling price manipulation via temporary pool imbalance.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_flash_loan_vulnerability() {
            vulnerabilities.push(LpTokenDirectOraclePricingVulnerability {
                location: loc,
                pricing_type: LpOraclePricingType::FlashLoanPriceAttack,
                severity: "Critical".to_string(),
                description: "LP valuation vulnerable to atomic flash loan attack. No reentrancy protection \
                             or multi-transaction requirement for price updates.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_direct_spot_price(&self) -> Option<usize> {
        // getReserves call without fair price formula
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // getReserves (0x0902f1ac)
                if selector == 0x0902f1ac {
                    // Check for fair price formula (needs SQRT operations)
                    let mut has_sqrt = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        // SQRT not native, but would involve EXP or complex math
                        if self.bytecode[j] == 0x0a { // EXP
                            has_sqrt = true;
                            break;
                        }
                    }
                    if !has_sqrt {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_reserves_manipulation(&self) -> Option<usize> {
        // STATICCALL to getReserves in same transaction as value usage
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if preceded by getReserves selector
                let mut is_reserves_call = false;
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                        let sel = u32::from_be_bytes([
                            self.bytecode[j + 1],
                            self.bytecode[j + 2],
                            self.bytecode[j + 3],
                            self.bytecode[j + 4],
                        ]);
                        if sel == 0x0902f1ac {
                            is_reserves_call = true;
                            break;
                        }
                    }
                }
                
                if is_reserves_call {
                    // Check for reentrancy guard
                    let mut has_guard = false;
                    for j in i.saturating_sub(25)..i {
                        if self.bytecode[j] == 0x54 && j + 1 < self.bytecode.len() {
                            if self.bytecode[j + 1] == 0x15 { // SLOAD, ISZERO
                                has_guard = true;
                                break;
                            }
                        }
                    }
                    if !has_guard {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_missing_fair_price(&self) -> Option<usize> {
        // Reserve ratio calculation without geometric mean
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x04 { // DIV (reserve0 / reserve1)
                // Check if this is LP valuation context
                let in_lp_context = i > 50 && {
                    let mut found = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x0902f1ac { // getReserves
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if in_lp_context {
                    // Check for MUL operations (fair price needs multiple multiplications)
                    let mut mul_count = 0;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 {
                            mul_count += 1;
                        }
                    }
                    if mul_count < 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_single_block_snapshot(&self) -> Option<usize> {
        // Reserve reading without block number tracking
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xfa { // STATICCALL to getReserves
                // Check for block.number usage (multi-block observation)
                let mut has_block_tracking = false;
                for j in i.saturating_sub(20)..std::cmp::min(i + 30, self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 { // NUMBER
                        has_block_tracking = true;
                        break;
                    }
                }
                if !has_block_tracking {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_no_twap(&self) -> Option<usize> {
        // Price calculation without time-weighted component
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x02 { // MUL (price calc)
                // Check for timestamp in calculation
                let mut has_time_component = false;
                for j in i.saturating_sub(30)..std::cmp::min(i + 30, self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        has_time_component = true;
                        break;
                    }
                }
                
                // If this is pricing logic without time component
                let is_pricing = i > 40 && {
                    let mut found = false;
                    for j in i.saturating_sub(40)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x0902f1ac {
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if is_pricing && !has_time_component {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_flash_loan_vulnerability(&self) -> Option<usize> {
        // LP value calculation without tx-level protection
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x04 || self.bytecode[i] == 0x02 { // DIV or MUL
                // Check for reentrancy guard or block delay
                let mut has_protection = false;
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (guard check)
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0x15 {
                            has_protection = true;
                            break;
                        }
                    }
                }
                
                // In LP pricing context without protection
                let is_lp_pricing = i > 40 && {
                    let mut found = false;
                    for j in i.saturating_sub(40)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x0902f1ac {
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if is_lp_pricing && !has_protection {
                    return Some(i);
                }
            }
        }
        None
    }
}
