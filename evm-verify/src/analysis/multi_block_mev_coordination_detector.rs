use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiBlockMevCoordinationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct MultiBlockMevCoordinationDetector {
    bytecode: Vec<u8>,
}

impl MultiBlockMevCoordinationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiBlockMevCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Multi-block MEV coordination extracts value across consecutive blocks
        // Detect state that incentivizes multi-block manipulation
        if let Some(location) = self.has_multi_block_manipulation_incentive() {
            vulnerabilities.push(MultiBlockMevCoordinationVulnerability {
                vulnerability_type: "Multi-Block MEV Coordination Incentive".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Protocol state allows validators to profit by manipulating multiple consecutive blocks. Coordinated block proposals can sandwich transactions across blocks or manipulate time-weighted oracles. Implement single-block atomicity or randomized ordering.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect time-weighted accumulation vulnerable to multi-block attacks
        if let Some(location) = self.has_multi_block_twap_manipulation() {
            vulnerabilities.push(MultiBlockMevCoordinationVulnerability {
                vulnerability_type: "Multi-Block TWAP Manipulation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Time-weighted average price updates every block without manipulation resistance. Validators controlling consecutive blocks can manipulate TWAP by coordinating prices across blocks. Use longer TWAP windows (>12 blocks) or commit-reveal.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect block-sequenced auctions vulnerable to coordination
        if let Some(location) = self.has_cross_block_auction_gaming() {
            vulnerabilities.push(MultiBlockMevCoordinationVulnerability {
                vulnerability_type: "Cross-Block Auction Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Auction settlement spans multiple blocks without validators' ability to coordinate. Block proposers can delay bids in one block and front-run in the next. Implement single-block atomic settlement or encrypted bids.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_multi_block_manipulation_incentive(&self) -> Option<usize> {
        // Pattern: Block-dependent state changes with high value locked
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for block number dependency
            if self.bytecode[i] == 0x43 { // NUMBER (block.number)
                // Check if used in state transition
                let mut affects_high_value_state = false;
                
                for j in i+1..i+35.min(self.bytecode.len()) {
                    // Look for storage write based on block number
                    if self.bytecode[j] == 0x55 { // SSTORE
                        // Check if value-related (preceded by BALANCE or large amounts)
                        for k in j.saturating_sub(20)..j {
                            if self.bytecode[k] == 0x47 || self.bytecode[k] == 0x31 { // SELFBALANCE or BALANCE
                                affects_high_value_state = true;
                                break;
                            }
                        }
                    }
                }
                
                if affects_high_value_state {
                    // Check if there's no multi-block protection (randomness, etc.)
                    let mut has_manipulation_protection = false;
                    
                    for j in i.saturating_sub(30)..i+30.min(self.bytecode.len()) {
                        // Look for randomness (BLOCKHASH, DIFFICULTY, etc.)
                        if self.bytecode[j] == 0x40 || self.bytecode[j] == 0x44 { // BLOCKHASH or DIFFICULTY
                            has_manipulation_protection = true;
                        }
                    }
                    
                    if !has_manipulation_protection {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_multi_block_twap_manipulation(&self) -> Option<usize> {
        // Pattern: Price accumulation with block number without sufficient history
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x43 { // NUMBER
                // Look for price accumulation pattern
                let mut has_price_accumulation = false;
                
                for j in i+1..i+40.min(self.bytecode.len()) {
                    // Price accumulation: oldAccumulator + price * timeDelta
                    if self.bytecode[j] == 0x01 { // ADD
                        // Check if preceded by MUL (price * time)
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] == 0x02 { // MUL
                                has_price_accumulation = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_price_accumulation {
                    // Check if window is too short (< 12 blocks)
                    let mut has_long_window = false;
                    
                    for j in i.saturating_sub(20)..i+30.min(self.bytecode.len()) {
                        // Look for large constant (long window)
                        if self.bytecode[j] >= 0x60 && self.bytecode[j] <= 0x7f { // PUSH
                            if j + 1 < self.bytecode.len() {
                                let value = self.bytecode[j + 1];
                                if value > 12 { // More than 12 blocks
                                    has_long_window = true;
                                }
                            }
                        }
                    }
                    
                    if !has_long_window {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_cross_block_auction_gaming(&self) -> Option<usize> {
        // Pattern: Auction settlement that spans multiple blocks
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for auction settlement
            if self.bytecode[i] == 0xf1 { // CALL (settlement transfer)
                // Check if auction timing depends on block number
                let mut depends_on_block_number = false;
                
                for j in i.saturating_sub(40)..i {
                    if self.bytecode[j] == 0x43 { // NUMBER
                        // Check if used in comparison (auction end)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x11 || self.bytecode[k] == 0x10 { // GT or LT
                                depends_on_block_number = true;
                                break;
                            }
                        }
                    }
                }
                
                if depends_on_block_number {
                    // Check if there's encrypted bid protection
                    let mut has_encryption = false;
                    
                    for j in i.saturating_sub(50)..i {
                        // Look for commit-reveal pattern (hash comparison)
                        if self.bytecode[j] == 0x20 { // SHA3
                            for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ (comparing hash)
                                    has_encryption = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_encryption {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
