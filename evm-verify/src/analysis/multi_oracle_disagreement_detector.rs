use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Multi-Oracle Price Disagreement Detection
/// 
/// Detects vulnerabilities when using multiple oracle sources:
/// 1. No price deviation check between oracles
/// 2. Single oracle failure causes system failure
/// 3. Median/average calculation without outlier removal
/// 4. Oracle weight manipulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiOracleDisagreementVulnerability {
    /// Critical: No deviation check between oracles
    MissingDeviationCheck {
        description: String,
        location: usize,
        oracle_count: u32,
        confidence: f32,
    },
    /// High: Single point of failure
    SingleOracleFailureRisk {
        description: String,
        location: usize,
        fallback_exists: bool,
    },
    /// High: Outlier not removed from aggregation
    NoOutlierRemoval {
        description: String,
        aggregation_location: usize,
        oracle_count: u32,
    },
    /// Medium: Oracle weights can be manipulated
    ManipulableOracleWeights {
        description: String,
        location: usize,
    },
}

pub struct MultiOracleDisagreementDetector {
    bytecode: Vec<u8>,
}

impl MultiOracleDisagreementDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiOracleDisagreementVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Find all oracle aggregation points
        let oracle_aggregations = self.find_oracle_aggregations();
        
        for (location, oracle_count) in oracle_aggregations {
            // Pattern 1: Check if prices are compared for deviation
            let has_deviation_check = self.has_price_deviation_check(location, location + 200);
            
            if !has_deviation_check && oracle_count > 1 {
                vulnerabilities.push(MultiOracleDisagreementVulnerability::MissingDeviationCheck {
                    description: format!(
                        "{} oracles used without price deviation validation",
                        oracle_count
                    ),
                    location,
                    oracle_count,
                    confidence: 0.90,
                });
            }
            
            // Pattern 2: Single oracle failure handling
            let has_fallback = self.has_oracle_fallback_logic(location, location + 150);
            let has_revert_on_fail = self.reverts_on_oracle_failure(location, location + 150);
            
            if has_revert_on_fail && !has_fallback {
                vulnerabilities.push(MultiOracleDisagreementVulnerability::SingleOracleFailureRisk {
                    description: "Single oracle failure causes transaction revert".to_string(),
                    location,
                    fallback_exists: false,
                });
            }
            
            // Pattern 3: Outlier removal in aggregation
            if oracle_count >= 3 {
                let has_outlier_removal = self.has_outlier_removal_logic(location, location + 200);
                
                if !has_outlier_removal {
                    vulnerabilities.push(MultiOracleDisagreementVulnerability::NoOutlierRemoval {
                        description: format!(
                            "Aggregating {} oracles without outlier removal",
                            oracle_count
                        ),
                        aggregation_location: location,
                        oracle_count,
                    });
                }
            }
        }
        
        // Pattern 4: Oracle weight manipulation
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_weighted_oracle_aggregation(i) {
                let weights_are_mutable = self.oracle_weights_are_mutable(i, i + 100);
                
                if weights_are_mutable {
                    vulnerabilities.push(MultiOracleDisagreementVulnerability::ManipulableOracleWeights {
                        description: "Oracle weights can be modified without timelock".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_oracle_aggregations(&self) -> Vec<(usize, u32)> {
        let mut aggregations = Vec::new();
        
        // Look for patterns indicating multiple oracle calls
        for i in 0..self.bytecode.len().saturating_sub(300) {
            let oracle_calls = self.count_oracle_calls_in_range(i, i + 300);
            
            if oracle_calls > 1 {
                // Verify this is an aggregation point by checking for arithmetic
                let has_aggregation = self.has_price_aggregation_logic(i, i + 300);
                
                if has_aggregation {
                    aggregations.push((i, oracle_calls));
                }
            }
        }
        
        aggregations
    }
    
    fn count_oracle_calls_in_range(&self, start: usize, end: usize) -> u32 {
        let range_end = end.min(self.bytecode.len());
        let mut count = 0;
        
        // Oracle call selectors:
        // latestRoundData: 0xfeaf968c
        // latestAnswer: 0x50d25bcd
        // getPrice: various
        
        for i in start..range_end.saturating_sub(4) {
            if self.bytecode[i] == 0x63 { // PUSH4 (selector)
                if i + 4 < range_end {
                    // Check if it's an oracle selector
                    if (self.bytecode[i + 1] == 0xfe && self.bytecode[i + 2] == 0xaf) || // latestRoundData
                       (self.bytecode[i + 1] == 0x50 && self.bytecode[i + 2] == 0xd2) || // latestAnswer
                       (self.bytecode[i + 1] == 0x41 && self.bytecode[i + 2] == 0x97) {  // getPrice
                        count += 1;
                    }
                }
            }
        }
        
        count
    }
    
    fn has_price_aggregation_logic(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Aggregation involves:
        // 1. Multiple prices
        // 2. ADD or DIV operations (for average/median)
        // 3. Result storage or return
        
        let has_add_or_div = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x01 || b == 0x04) // ADD or DIV
            .count() > 1;
        
        let has_mul = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x02); // MUL (for weighted average)
        
        has_add_or_div || has_mul
    }
    
    fn has_price_deviation_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Deviation check pattern:
        // 1. SUB (price1 - price2)
        // 2. MUL with 100 or 10000 (percentage calculation)
        // 3. DIV (deviation / price)
        // 4. Comparison (LT/GT) with threshold
        // 5. REVERT if too large
        
        let mut has_subtraction = false;
        let mut has_percentage_calc = false;
        let mut has_comparison = false;
        let mut has_revert = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x03 { // SUB
                has_subtraction = true;
            }
            if self.bytecode[i] == 0x02 && i + 2 < range_end { // MUL
                // Check if multiplied by percentage constant (100, 1000, 10000)
                if self.bytecode[i - 2] == 0x60 { // PUSH1
                    let val = self.bytecode[i - 1];
                    if val == 100 || val == 64 { // 100 or 0x64
                        has_percentage_calc = true;
                    }
                }
            }
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                has_comparison = true;
            }
            if self.bytecode[i] == 0xfd { // REVERT
                has_revert = true;
            }
        }
        
        has_subtraction && has_percentage_calc && has_comparison && has_revert
    }
    
    fn has_oracle_fallback_logic(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Fallback logic patterns:
        // 1. Try-catch pattern (multiple JUMPI)
        // 2. Secondary oracle call after failure
        // 3. Cached price usage
        
        let jumpi_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x57) // JUMPI
            .count();
        
        let has_cached_price = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x54) // SLOAD (loading cached price)
            .count() > 1;
        
        jumpi_count > 3 || has_cached_price
    }
    
    fn reverts_on_oracle_failure(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if oracle failure (returndatasize == 0) causes REVERT
        self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x3d && // RETURNDATASIZE
                w[1] == 0x15 && // ISZERO
                w[2] == 0xfd    // REVERT
            })
    }
    
    fn has_outlier_removal_logic(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Outlier removal typically involves:
        // 1. Sorting prices (multiple comparisons)
        // 2. Removing min/max
        // 3. Or using median (middle value)
        
        let comparison_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x10 || b == 0x11) // LT or GT
            .count();
        
        // Need at least 3 comparisons for sorting 3+ values
        // Or specific median calculation pattern
        comparison_count >= 3
    }
    
    fn is_weighted_oracle_aggregation(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Weighted aggregation uses MUL for weights
        // Pattern: price * weight / totalWeight
        
        let has_mul = self.bytecode[location..location + 50]
            .iter()
            .any(|&b| b == 0x02); // MUL
        
        let has_div = self.bytecode[location..location + 50]
            .iter()
            .any(|&b| b == 0x04); // DIV
        
        let has_oracle_call = self.bytecode[location..location + 50]
            .windows(4)
            .any(|w| w[0] == 0x63 && w[1] == 0xfe);
        
        has_mul && has_div && has_oracle_call
    }
    
    fn oracle_weights_are_mutable(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if weights can be modified:
        // 1. Look for setWeight() or similar functions
        // 2. Check if there's a timelock on weight changes
        
        let has_weight_setter = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x63 && // Function selector
                w.iter().any(|&b| b == 0x55) // SSTORE (storing new weight)
            });
        
        if !has_weight_setter {
            return false;
        }
        
        // Check for timelock protection
        let has_timelock = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x10    // LT (comparison)
            });
        
        has_weight_setter && !has_timelock
    }
}
