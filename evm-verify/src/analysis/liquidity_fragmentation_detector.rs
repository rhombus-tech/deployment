use serde::{Serialize, Deserialize};

/// Liquidity Fragmentation Detection
/// 
/// Detects when liquidity is split across multiple pools/venues causing:
/// 1. Higher slippage than necessary
/// 2. Cross-DEX arbitrage vulnerabilities
/// 3. Inefficient capital allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityFragmentationDetectorVulnerability {
    /// Critical: Multiple pool interactions without aggregation
    MultiPoolNoAggregation {
        description: String,
        location: usize,
        pool_count: usize,
    },
    /// High: No slippage protection across pools
    CrossPoolSlippageRisk {
        description: String,
        location: usize,
    },
}

pub struct LiquidityFragmentationDetector {
    bytecode: Vec<u8>,
}

impl LiquidityFragmentationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityFragmentationDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect multiple external calls to different pools
        let external_calls = self.find_external_calls();
        
        if external_calls.len() >= 3 {
            // Check if these are to different addresses (different pools)
            let unique_targets = self.count_unique_call_targets(&external_calls);
            
            if unique_targets >= 2 {
                // Check for aggregation logic
                let has_aggregation = self.has_price_aggregation(&external_calls);
                
                if !has_aggregation {
                    vulnerabilities.push(LiquidityFragmentationDetectorVulnerability::MultiPoolNoAggregation {
                        description: format!(
                            "Interacts with {} pools without price aggregation",
                            unique_targets
                        ),
                        location: external_calls[0],
                        pool_count: unique_targets,
                    });
                }
            }
        }
        
        // Pattern 2: Check for slippage protection across pools
        for call_loc in external_calls {
            let has_slippage = self.has_slippage_check_near(call_loc);
            
            if !has_slippage {
                vulnerabilities.push(LiquidityFragmentationDetectorVulnerability::CrossPoolSlippageRisk {
                    description: "Pool interaction without slippage protection".to_string(),
                    location: call_loc,
                });
                break; // Report once
            }
        }
        
        vulnerabilities
    }
    
    fn find_external_calls(&self) -> Vec<usize> {
        let mut calls = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL or STATICCALL
                calls.push(i);
            }
        }
        
        calls
    }
    
    fn count_unique_call_targets(&self, calls: &[usize]) -> usize {
        // Heuristic: if calls are far apart, likely different targets
        if calls.len() < 2 {
            return calls.len();
        }
        
        let mut unique = 1;
        for i in 1..calls.len() {
            if calls[i] - calls[i-1] > 100 {
                unique += 1;
            }
        }
        
        unique
    }
    
    fn has_price_aggregation(&self, calls: &[usize]) -> bool {
        if calls.is_empty() {
            return false;
        }
        
        // Look for aggregation patterns: multiple results combined
        let start = calls[0];
        let end = calls.last().map(|&l| l + 50).unwrap_or(self.bytecode.len());
        let end = std::cmp::min(end, self.bytecode.len());
        
        // Check for ADD or MUL combining results
        self.bytecode[start..end]
            .windows(3)
            .filter(|w| w[0] == 0x01 || w[0] == 0x02) // ADD or MUL
            .count() >= 2
    }
    
    fn has_slippage_check_near(&self, location: usize) -> bool {
        let start = location.saturating_sub(30);
        let end = std::cmp::min(location + 30, self.bytecode.len());
        
        self.bytecode[start..end]
            .windows(2)
            .any(|w| w[0] == 0x10 || w[0] == 0x11) // LT or GT
    }
}
