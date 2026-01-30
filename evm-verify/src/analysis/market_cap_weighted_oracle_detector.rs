use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketCapWeightedOracleVulnerability {
    pub location: usize,
    pub oracle_type: MarketCapOracleType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MarketCapOracleType {
    ManipulableWeighting,            // Market cap weighting manipulable
    CirculatingSupplyManipulation,   // Circulating supply not accurate
    PriceOracleManipulation,         // Underlying price oracle manipulated
    IndexRebalanceExploit,           // Exploit during rebalance
    FlashLoanWeightAttack,           // Flash loan to manipulate weights
    StalePriceData,                  // Stale market cap data used
}

pub struct MarketCapWeightedOracleDetector {
    bytecode: Vec<u8>,
}

impl MarketCapWeightedOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MarketCapWeightedOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_manipulable_weighting() {
            vulnerabilities.push(MarketCapWeightedOracleVulnerability {
                location: loc,
                oracle_type: MarketCapOracleType::ManipulableWeighting,
                severity: "Critical".to_string(),
                description: "Market cap weighted index oracle vulnerable to manipulation. Indexed Finance \
                             $16M exploit: attacker manipulated low-liquidity token market cap to change \
                             index weights. MUST use TWAP and validate liquidity.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_circulating_supply_manipulation() {
            vulnerabilities.push(MarketCapWeightedOracleVulnerability {
                location: loc,
                oracle_type: MarketCapOracleType::CirculatingSupplyManipulation,
                severity: "High".to_string(),
                description: "Circulating supply used for market cap without validation. Attacker can burn \
                             tokens to manipulate supply metric, affecting index weights.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_price_oracle_manipulation() {
            vulnerabilities.push(MarketCapWeightedOracleVulnerability {
                location: loc,
                oracle_type: MarketCapOracleType::PriceOracleManipulation,
                severity: "Critical".to_string(),
                description: "Underlying price oracle for market cap calculation manipulable. Uses spot \
                             price without TWAP, enabling flash loan price manipulation.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_index_rebalance_exploit() {
            vulnerabilities.push(MarketCapWeightedOracleVulnerability {
                location: loc,
                oracle_type: MarketCapOracleType::IndexRebalanceExploit,
                severity: "High".to_string(),
                description: "Index rebalancing vulnerable to front-running. Predictable rebalance allows \
                             MEV extraction by anticipating weight changes.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_flash_loan_weight_attack() {
            vulnerabilities.push(MarketCapWeightedOracleVulnerability {
                location: loc,
                oracle_type: MarketCapOracleType::FlashLoanWeightAttack,
                severity: "Critical".to_string(),
                description: "Flash loan can manipulate token weight in single transaction. No protection \
                             against atomic price+supply manipulation to change index composition.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_stale_price_data() {
            vulnerabilities.push(MarketCapWeightedOracleVulnerability {
                location: loc,
                oracle_type: MarketCapOracleType::StalePriceData,
                severity: "Medium".to_string(),
                description: "Market cap calculation uses stale price data. No staleness check allows using \
                             outdated prices for weight calculation.".to_string(),
                confidence: 0.84,
            });
        }

        vulnerabilities
    }

    fn detect_manipulable_weighting(&self) -> Option<usize> {
        // Market cap calculation without TWAP
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // MUL (price * supply = market cap)
            if self.bytecode[i] == 0x02 {
                // Check if price comes from spot oracle (STATICCALL without time averaging)
                let mut has_spot_price = false;
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0xfa { // STATICCALL (oracle query)
                        has_spot_price = true;
                        break;
                    }
                }
                
                if has_spot_price {
                    // Check for TWAP (multiple price samples)
                    let mut has_twap = false;
                    for j in i.saturating_sub(30)..i {
                        if self.bytecode[j] == 0x04 { // DIV (averaging prices)
                            has_twap = true;
                            break;
                        }
                    }
                    if !has_twap {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_circulating_supply_manipulation(&self) -> Option<usize> {
        // Total supply used without burn verification
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // totalSupply (0x18160ddd), getCirculatingSupply (0x9358928b)
                if selector == 0x18160ddd || selector == 0x9358928b {
                    // Check if result is validated (not just trusted)
                    let mut has_validation = false;
                    for j in i..std::cmp::min(i + 30, self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT check
                            has_validation = true;
                            break;
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

    fn detect_price_oracle_manipulation(&self) -> Option<usize> {
        // Oracle call without multi-block validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle)
                // Check if using single-block price
                let mut has_block_check = false;
                for j in i.saturating_sub(20)..std::cmp::min(i + 30, self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 { // NUMBER (block.number)
                        has_block_check = true;
                        break;
                    }
                }
                
                // Single block price without time-weighting
                if !has_block_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_index_rebalance_exploit(&self) -> Option<usize> {
        // Rebalance function without delay
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // rebalance (0xf337d6a8), updateWeights (0x0d43e8ad)
                if selector == 0xf337d6a8 || selector == 0x0d43e8ad {
                    // Check for commit-reveal or delay
                    let mut has_delay = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP (delay check)
                            has_delay = true;
                            break;
                        }
                    }
                    if !has_delay {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_flash_loan_weight_attack(&self) -> Option<usize> {
        // Weight calculation in same transaction as price update
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x02 { // MUL (weight calculation)
                // Check for reentrancy guard or block delay
                let mut has_protection = false;
                for j in i.saturating_sub(30)..i {
                    // Look for storage read (reentrancy guard)
                    if self.bytecode[j] == 0x54 {
                        // Check if it's a guard pattern (SLOAD, ISZERO)
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0x15 {
                            has_protection = true;
                            break;
                        }
                    }
                }
                if !has_protection {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_stale_price_data(&self) -> Option<usize> {
        // Price usage without timestamp check
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xfa { // STATICCALL (price oracle)
                // Check for timestamp staleness validation
                let mut has_staleness_check = false;
                for j in i..std::cmp::min(i + 30, self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Check if compared (staleness check)
                        for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                            if matches!(self.bytecode[k], 0x10 | 0x11) {
                                has_staleness_check = true;
                                break;
                            }
                        }
                        if has_staleness_check {
                            break;
                        }
                    }
                }
                if !has_staleness_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
