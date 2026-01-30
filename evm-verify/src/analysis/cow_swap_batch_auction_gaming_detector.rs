use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowSwapBatchAuctionGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct CowSwapBatchAuctionGamingDetector {
    bytecode: Vec<u8>,
}

impl CowSwapBatchAuctionGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CowSwapBatchAuctionGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // CoW Swap uses batch auctions with solvers competing
        // Detect solver collusion in batch auctions
        if let Some(location) = self.has_solver_collusion_risk() {
            vulnerabilities.push(CowSwapBatchAuctionGamingVulnerability {
                vulnerability_type: "CoW Swap Solver Collusion".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Batch auction solver selection without collusion prevention. Solvers can coordinate to submit non-competitive bids and share MEV. Implement solver reputation and bid randomization.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect batch manipulation through order inclusion
        if let Some(location) = self.has_order_inclusion_manipulation() {
            vulnerabilities.push(CowSwapBatchAuctionGamingVulnerability {
                vulnerability_type: "CoW Swap Order Inclusion Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Solver can selectively include/exclude orders from batch for MEV. Cherry-picking profitable orders while excluding unprofitable creates unfair execution. Require uniform order inclusion or economic penalties.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect uniform clearing price manipulation
        if let Some(location) = self.has_clearing_price_gaming() {
            vulnerabilities.push(CowSwapBatchAuctionGamingVulnerability {
                vulnerability_type: "CoW Swap Clearing Price Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Uniform clearing price calculated without manipulation resistance. Solvers can add wash trades to manipulate batch clearing price. Implement outlier detection and price bounds.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_solver_collusion_risk(&self) -> Option<usize> {
        // Pattern: Solver selection without diversity enforcement
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for solver payment/reward
            if self.bytecode[i] == 0xf1 { // CALL (solver payment)
                // Check if solver is validated for uniqueness/reputation
                let mut validates_solver_reputation = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for solver reputation check
                    if self.bytecode[j] == 0x54 { // SLOAD (solver data)
                        // Check if reputation/history verified
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT (reputation threshold)
                                validates_solver_reputation = true;
                                break;
                            }
                        }
                    }
                }
                
                if !validates_solver_reputation {
                    // Verify this is solver-related (batch settlement)
                    for j in i.saturating_sub(35)..i {
                        // Look for batch processing (multiple orders)
                        if self.bytecode[j] == 0x5b { // JUMPDEST (loop processing orders)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_order_inclusion_manipulation(&self) -> Option<usize> {
        // Pattern: Selective order processing in batch
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for order processing loop
            if self.bytecode[i] == 0x5b { // JUMPDEST (batch loop)
                // Check if orders can be skipped based on profitability
                let mut has_profitability_filter = false;
                
                for j in i+1..i+40.min(self.bytecode.len()) {
                    // Look for conditional execution of orders
                    if self.bytecode[j] == 0x57 { // JUMPI (skipping order)
                        // Check if condition is profit-based
                        for k in j.saturating_sub(20)..j {
                            // Look for profit calculation (price difference, etc.)
                            if self.bytecode[k] == 0x03 { // SUB (price difference)
                                has_profitability_filter = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_profitability_filter {
                    // Check if there's penalty for exclusion
                    let mut has_exclusion_penalty = false;
                    
                    for j in i+1..i+45.min(self.bytecode.len()) {
                        // Look for penalty calculation
                        if self.bytecode[j] == 0x02 { // MUL (penalty * excluded_count)
                            has_exclusion_penalty = true;
                        }
                    }
                    
                    if !has_exclusion_penalty {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_clearing_price_gaming(&self) -> Option<usize> {
        // Pattern: Uniform clearing price without outlier protection
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for clearing price calculation (averaging)
            if self.bytecode[i] == 0x04 { // DIV (sum / count = average)
                // Check if this is price calculation
                let mut is_price_calculation = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for price accumulation (ADD in loop)
                    if self.bytecode[j] == 0x01 { // ADD (accumulating prices)
                        is_price_calculation = true;
                        break;
                    }
                }
                
                if is_price_calculation {
                    // Check for outlier detection
                    let mut has_outlier_detection = false;
                    
                    for j in i.saturating_sub(40)..i+30.min(self.bytecode.len()) {
                        // Look for price bounds checking
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                            // Check if followed by conditional (filtering outliers)
                            for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x57 { // JUMPI (skipping outlier)
                                    has_outlier_detection = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_outlier_detection {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
