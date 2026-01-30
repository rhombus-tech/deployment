use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapxDutchAuctionGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct UniswapxDutchAuctionGamingDetector {
    bytecode: Vec<u8>,
}

impl UniswapxDutchAuctionGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UniswapxDutchAuctionGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // UniswapX uses Dutch auctions for order filling
        // Detect price curve manipulation for MEV
        if let Some(location) = self.has_price_curve_gaming() {
            vulnerabilities.push(UniswapxDutchAuctionGamingVulnerability {
                vulnerability_type: "UniswapX Dutch Auction Price Curve Gaming".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Dutch auction price curve allows fillers to wait for optimal execution price. Fillers can extract MEV by timing fills at most profitable curve point. Implement discrete price steps or faster decay.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect cross-order arbitrage via selective filling
        if let Some(location) = self.has_cross_order_arbitrage() {
            vulnerabilities.push(UniswapxDutchAuctionGamingVulnerability {
                vulnerability_type: "UniswapX Cross-Order Arbitrage".to_string(),
                location,
                severity: "High".to_string(),
                description: "Fillers can selectively choose orders to create arbitrage opportunities. Filling orders in specific sequence extracts value across multiple swaps. Implement batch settlement or order isolation.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect last-look option exploitation
        if let Some(location) = self.has_last_look_exploitation() {
            vulnerabilities.push(UniswapxDutchAuctionGamingVulnerability {
                vulnerability_type: "UniswapX Last-Look Option Exploitation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Fillers have free option to fill at any point during auction. Can observe market and only fill when profitable without commitment. Require filler bonds or commitment mechanisms.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_price_curve_gaming(&self) -> Option<usize> {
        // Pattern: Price calculation based on time without manipulation resistance
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for time-based price calculation
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in price calculation
                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 { // SUB (elapsed time)
                        // Check if used to calculate current price
                        for k in j+1..(j+20).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x02 || self.bytecode[k] == 0x04 { // MUL or DIV
                                // Check if price decay is fast enough or discrete
                                let mut has_fast_decay = false;
                                
                                for m in k.saturating_sub(15)..k {
                                    // Look for decay factor (should be large for fast decay)
                                    if self.bytecode[m] >= 0x60 && self.bytecode[m] <= 0x7f { // PUSH
                                        // This is heuristic - checking if decay factor exists
                                        has_fast_decay = true;
                                    }
                                }
                                
                                // Or check for discrete steps (MOD operation)
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x06 { // MOD (discrete steps)
                                        has_fast_decay = true;
                                    }
                                }
                                
                                if !has_fast_decay {
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_cross_order_arbitrage(&self) -> Option<usize> {
        // Pattern: Independent order filling without batch settlement
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for order fill (transfer execution)
            if self.bytecode[i] == 0xf1 { // CALL (executing fill)
                // Check if orders are processed independently
                let mut is_independent_fill = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for single order ID
                    if self.bytecode[j] == 0x35 { // CALLDATALOAD (order ID)
                        is_independent_fill = true;
                        break;
                    }
                }
                
                if is_independent_fill {
                    // Check if batch settlement enforced
                    let mut has_batch_settlement = false;
                    
                    for j in i.saturating_sub(45)..i {
                        // Look for multiple order processing (loop)
                        if self.bytecode[j] == 0x5b { // JUMPDEST (batch loop)
                            has_batch_settlement = true;
                        }
                    }
                    
                    if !has_batch_settlement {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_last_look_exploitation(&self) -> Option<usize> {
        // Pattern: Fill execution without filler commitment/bond
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for fill authorization
            if self.bytecode[i] == 0xf1 { // CALL (fill execution)
                // Check if filler has posted bond
                let mut requires_bond = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for bond/collateral check
                    if self.bytecode[j] == 0x54 { // SLOAD (filler bond)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 { // LT (bond >= minimum)
                                requires_bond = true;
                                break;
                            }
                        }
                    }
                    // Or payment upfront
                    if self.bytecode[j] == 0x34 { // CALLVALUE (filler payment)
                        requires_bond = true;
                    }
                }
                
                if !requires_bond {
                    // Verify this is dutch auction fill (time-based price)
                    for j in i.saturating_sub(40)..i {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP (auction timing)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
