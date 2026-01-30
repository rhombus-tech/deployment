use serde::{Serialize, Deserialize};

/// Cross-Protocol MEV Coordination Detection
/// 
/// Detects patterns where actions across multiple protocols can be coordinated
/// for MEV extraction. This is emerging as MEV becomes more sophisticated:
/// 
/// 1. Atomic multi-protocol swaps
/// 2. Cross-protocol arbitrage paths
/// 3. Liquidation cascades across protocols
/// 4. Oracle manipulation affecting multiple protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossProtocolMevCoordinationVulnerability {
    /// Critical: Atomic cross-protocol dependency
    AtomicCrossProtocolRisk {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Price oracle shared across protocols
    SharedOracleManipulation {
        description: String,
        location: usize,
    },
    /// High: Liquidation triggers cross-protocol cascade
    LiquidationCascadeRisk {
        description: String,
        location: usize,
    },
    /// Medium: State update ordering exploitable
    ExploitableOrdering {
        description: String,
        location: usize,
    },
    /// Medium: Missing cross-protocol flash loan protection
    MissingCrossProtocolProtection {
        description: String,
        location: usize,
    },
}

pub struct CrossProtocolMevCoordinationDetector {
    bytecode: Vec<u8>,
}

impl CrossProtocolMevCoordinationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossProtocolMevCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect multiple external protocol calls in one transaction
        // Pattern: Multiple CALL/DELEGATECALL to different addresses
        let external_calls = self.find_external_calls();
        
        if external_calls.len() >= 2 {
            // Check if these calls are in a single transaction flow
            let are_atomic = self.are_calls_atomic(&external_calls);
            
            if are_atomic {
                vulnerabilities.push(CrossProtocolMevCoordinationVulnerability::AtomicCrossProtocolRisk {
                    description: format!(
                        "Function makes {} external calls atomically - MEV coordination risk",
                        external_calls.len()
                    ),
                    location: external_calls[0],
                    confidence: 0.75,
                });
            }
        }
        
        // Pattern 2: Check for oracle price reads from external contracts
        // ChainLink, Uniswap TWAP, or other oracle patterns
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for STATICCALL (oracle read)
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if return value is used in financial calculation
                let used_in_calc = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .windows(3)
                    .any(|w| {
                        w[0] == 0x02 || w[0] == 0x04 // MUL or DIV
                    });
                
                if used_in_calc {
                    // Check if there's slippage protection
                    let has_slippage = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .windows(2)
                        .any(|w| w[0] == 0x10 || w[0] == 0x11); // LT or GT
                    
                    if !has_slippage {
                        vulnerabilities.push(CrossProtocolMevCoordinationVulnerability::SharedOracleManipulation {
                            description: "Oracle price used without slippage protection - cross-protocol MEV possible".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 3: Check for liquidation functions
        // liquidate(), liquidateBorrow(), etc.
        let liquidation_selectors = [
            0x96cd4ddb, // liquidateBorrow (Compound-style)
            0x5a8f3a79, // liquidate
        ];
        
        for selector in liquidation_selectors {
            if let Some(loc) = self.find_function_selector(selector) {
                // Check if liquidation reads external price
                let reads_external_price = self.bytecode[loc..std::cmp::min(loc+100, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0xfa || b == 0xf1); // STATICCALL or CALL
                
                if reads_external_price {
                    // Check for cascade protection
                    let has_cascade_protection = self.has_circuit_breaker(loc);
                    
                    if !has_cascade_protection {
                        vulnerabilities.push(CrossProtocolMevCoordinationVulnerability::LiquidationCascadeRisk {
                            description: "Liquidation function without cascade protection - multi-protocol risk".to_string(),
                            location: loc,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for swap routing through multiple DEXes
        // This is common in aggregators but risky for MEV
        for i in 0..self.bytecode.len().saturating_sub(150) {
            // Look for multiple swap-like operations
            let swap_count = self.count_swap_operations(i, 150);
            
            if swap_count >= 2 {
                // Check if there's front-run protection
                let has_deadline = self.has_deadline_check(i, 150);
                let has_min_output = self.has_minimum_output_check(i, 150);
                
                if !has_deadline || !has_min_output {
                    vulnerabilities.push(CrossProtocolMevCoordinationVulnerability::ExploitableOrdering {
                        description: format!(
                            "Multi-hop swap ({} hops) without adequate MEV protection",
                            swap_count
                        ),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 5: Check for flash loan functions
        // Flash loans enable cross-protocol attacks
        let flash_loan_selectors = [
            0x5cffe9de, // flashLoan (Aave)
            0x0b52a8c8, // flashLoan (Balancer)
        ];
        
        for selector in flash_loan_selectors {
            if let Some(loc) = self.find_function_selector(selector) {
                // Check if flash loan can interact with other protocols
                let has_arbitrary_call = self.has_arbitrary_external_call(loc, 150);
                
                if has_arbitrary_call {
                    vulnerabilities.push(CrossProtocolMevCoordinationVulnerability::MissingCrossProtocolProtection {
                        description: "Flash loan function allows arbitrary cross-protocol calls".to_string(),
                        location: loc,
                    });
                }
            }
        }
        
        // Pattern 6: Check for cross-protocol state dependencies
        for i in 0..self.bytecode.len().saturating_sub(80) {
            // Look for: External call -> SLOAD -> Use in calculation
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa {
                let reads_state_after = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x54); // SLOAD
                
                if reads_state_after {
                    let uses_in_critical_op = self.bytecode[i..std::cmp::min(i+80, self.bytecode.len())]
                        .windows(4)
                        .any(|w| {
                            // SLOAD -> arithmetic -> CALL/SSTORE
                            w[0] == 0x54 &&
                            (w[1] == 0x02 || w[1] == 0x04) &&
                            (w[2] == 0xf1 || w[2] == 0x55)
                        });
                    
                    if uses_in_critical_op {
                        vulnerabilities.push(CrossProtocolMevCoordinationVulnerability::AtomicCrossProtocolRisk {
                            description: "State read after external call used in critical operation - coordination risk".to_string(),
                            location: i,
                            confidence: 0.80,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_external_calls(&self) -> Vec<usize> {
        let mut locations = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xf1 || // CALL
               self.bytecode[i] == 0xf4 || // DELEGATECALL
               self.bytecode[i] == 0xfa {  // STATICCALL
                locations.push(i);
            }
        }
        
        locations
    }
    
    fn are_calls_atomic(&self, calls: &[usize]) -> bool {
        if calls.len() < 2 {
            return false;
        }
        
        // Check if calls are within a reasonable distance (same function)
        let distance = calls[calls.len() - 1] - calls[0];
        distance < 500 // Heuristic: within 500 bytes suggests same function
    }
    
    fn has_circuit_breaker(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for state variable that can pause operations
        self.bytecode[location..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x54 && // SLOAD (pause flag)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (revert if paused)
            })
    }
    
    fn count_swap_operations(&self, start: usize, range: usize) -> usize {
        let end = std::cmp::min(start + range, self.bytecode.len());
        
        // Count external calls that look like swaps
        self.bytecode[start..end]
            .iter()
            .filter(|&&b| b == 0xf1) // CALL
            .count()
    }
    
    fn has_deadline_check(&self, start: usize, range: usize) -> bool {
        let end = std::cmp::min(start + range, self.bytecode.len());
        
        // Look for TIMESTAMP comparison
        self.bytecode[start..end]
            .windows(3)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                (w[1] == 0x10 || w[1] == 0x11) // LT or GT
            })
    }
    
    fn has_minimum_output_check(&self, start: usize, range: usize) -> bool {
        let end = std::cmp::min(start + range, self.bytecode.len());
        
        // Look for comparison after swap (amount >= minAmount)
        self.bytecode[start..end]
            .windows(2)
            .filter(|w| w[0] == 0x10 || w[0] == 0x11) // LT or GT
            .count() >= 2 // At least 2 comparisons
    }
    
    fn has_arbitrary_external_call(&self, start: usize, range: usize) -> bool {
        let end = std::cmp::min(start + range, self.bytecode.len());
        
        // Look for CALL where target comes from calldata
        for i in start..end.saturating_sub(20) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                // Check if this is used as CALL target
                let used_in_call = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0xf1); // CALL
                
                if used_in_call {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn find_function_selector(&self, selector: u32) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let found = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                if found == selector {
                    return Some(i);
                }
            }
        }
        None
    }
}
