use serde::{Serialize, Deserialize};

/// Read-Only Reentrancy V2 Detection (Advanced pattern)
/// 
/// New attack vector where view/pure functions are called during reentrancy
/// to read inconsistent state. Different from classic read-only reentrancy:
/// 
/// 1. Victim calls attacker
/// 2. Attacker reenters through view function
/// 3. View function reads state mid-update (inconsistent)
/// 4. Attacker uses this data for profitable actions elsewhere
/// 
/// Examples: Balancer/Curve oracle manipulation, Sentiment exploit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadOnlyReentrancyV2Vulnerability {
    /// Critical: View function callable during state update
    ViewDuringStateUpdate {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Oracle/price function not protected
    UnprotectedOracleRead {
        description: String,
        location: usize,
    },
    /// High: Getter function reads multiple related states
    InconsistentMultiRead {
        description: String,
        location: usize,
    },
    /// High: No reentrancy guard on view functions
    UnguardedViewFunction {
        description: String,
        location: usize,
    },
    /// Medium: State snapshot not used
    MissingStateSnapshot {
        description: String,
        location: usize,
    },
}

pub struct ReadOnlyReentrancyV2Detector {
    bytecode: Vec<u8>,
}

impl ReadOnlyReentrancyV2Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }}

    pub fn detect_vulnerabilities(&self) -> Vec<ReadOnlyReentrancyV2Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Find view/pure functions (STATICCALL patterns)
        // These should not be callable during state updates
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if this is a getter/oracle function
                let reads_multiple_slots = self.counts_storage_reads(i, 60) > 1;
                
                if reads_multiple_slots {
                    // Check if there's reentrancy protection
                    let has_lock = self.has_reentrancy_lock(i);
                    
                    if !has_lock {
                        vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::InconsistentMultiRead {
                            description: "View function reads multiple storage slots without reentrancy protection".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Find price/oracle getter functions
        // Common patterns: getPrice, getReserves, totalAssets, balanceOf(this)
        let oracle_functions = self.find_oracle_functions();
        
        for func_loc in oracle_functions {
            // Check if callable during callbacks
            let protected_from_callback = self.is_protected_from_callback(func_loc);
            
            if !protected_from_callback {
                vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::UnprotectedOracleRead {
                    description: "Oracle/price function not protected from callback reentrancy".to_string(),
                    location: func_loc,
                });
            }
        }
        
        // Pattern 3: Check functions that read state after external calls
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Look for SLOAD after the call (reading state after callback)
                let reads_after_call = self.bytecode[i+1..std::cmp::min(i+40, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x54); // SLOAD
                
                if reads_after_call {
                    // Check if the state read is used in calculations
                    let used_in_calc = self.bytecode[i+1..std::cmp::min(i+80, self.bytecode.len())]
                        .windows(3)
                        .any(|w| {
                            w[0] == 0x54 && // SLOAD
                            (w[1] == 0x02 || w[1] == 0x04 || w[1] == 0x01) // MUL, DIV, or ADD
                        });
                    
                    if used_in_calc {
                        vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::ViewDuringStateUpdate {
                            description: "State read after external call and used in calculations - callback can manipulate".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for view functions without reentrancy guards
        // Look for function selectors that seem like getters
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // Check if this looks like a view function
                let is_view_function = self.looks_like_view_function(i, selector);
                
                if is_view_function {
                    // Check for reentrancy guard
                    let has_guard = self.has_reentrancy_lock(i);
                    
                    // Check if it reads multiple related pieces of state
                    let reads_count = self.counts_storage_reads(i, 50);
                    
                    if !has_guard && reads_count >= 2 {
                        vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::UnguardedViewFunction {
                            description: format!(
                                "View function (0x{:08x}) reads {} storage slots without reentrancy protection",
                                selector, reads_count
                            ),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 5: Check for AMM-style getters (reserves, prices, etc.)
        // getReserves: 0x0902f1ac, getPrice variations
        let critical_getters = [
            0x0902f1ac, // getReserves
            0x01e1d114, // totalAssets
            0x70a08231, // balanceOf
        ];
        
        for selector in critical_getters {
            if let Some(loc) = self.find_function_selector(selector) {
                // These are critical for pricing - must be protected
                let has_protection = self.has_read_lock_or_snapshot(loc);
                
                if !has_protection {
                    vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::UnprotectedOracleRead {
                        description: format!(
                            "Critical getter (0x{:08x}) lacks read lock or snapshot protection",
                            selector
                        ),
                        location: loc,
                    });
                }
            }
        }
        
        // Pattern 6: Check for missing state snapshots in multi-step operations
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for sequences: SLOAD, operation, CALL, SLOAD (same slot)
            if self.bytecode[i] == 0x54 { // SLOAD
                // Get the slot being read
                let slot = self.get_storage_slot_at(i);
                
                if let Some(slot_val) = slot {
                    // Look for external call
                    let call_offset = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .iter()
                        .position(|&b| b == 0xf1 || b == 0xf4);
                    
                    if let Some(call_pos) = call_offset {
                        // Check if same slot read again after call
                        let reads_same_after = self.reads_slot_after(i + call_pos, slot_val, 40);
                        
                        if reads_same_after {
                            vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::MissingStateSnapshot {
                                description: "Storage slot read before and after external call - should use snapshot".to_string(),
                                location: i,
                            });
                        }
                    }
                }
            }
        }
        
        // Pattern 7: Balancer-style vulnerability
        // Reading pool balances during withdrawal callback
        for i in 0..self.bytecode.len().saturating_sub(70) {
            // Look for BALANCE opcode (reading ETH/token balance)
            if self.bytecode[i] == 0x31 { // BALANCE
                // Check if this is used for calculations
                let used_in_div = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(2)
                    .any(|w| w[0] == 0x04); // DIV
                
                if used_in_div {
                    // Check if callable during callback
                    let has_callback_protection = self.has_reentrancy_lock(i.saturating_sub(30));
                    
                    if !has_callback_protection {
                        vulnerabilities.push(ReadOnlyReentrancyV2Vulnerability::ViewDuringStateUpdate {
                            description: "Balance read used in price calculation without callback protection".to_string(),
                            location: i,
                            confidence: 0.80,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_reentrancy_lock(&self, location: usize) -> bool {
        let start = location.saturating_sub(30);
        let end = std::cmp::min(location + 30, self.bytecode.len());
        
        self.bytecode[start..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x54 && // SLOAD
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI
            })
    }
    
    fn counts_storage_reads(&self, start: usize, range: usize) -> usize {
        let end = std::cmp::min(start + range, self.bytecode.len());
        self.bytecode[start..end]
            .iter()
            .filter(|&&b| b == 0x54)
            .count()
    }
    
    fn find_oracle_functions(&self) -> Vec<usize> {
        let mut locations = Vec::new();
        
        // Look for functions that:
        // 1. Read storage
        // 2. Perform calculations (MUL/DIV)
        // 3. Return value (RETURN)
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let has_sload = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x54);
                
                let has_math = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x02 || b == 0x04); // MUL or DIV
                
                let has_return = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0xf3);
                
                if has_sload && has_math && has_return {
                    locations.push(i);
                }
            }
        }
        
        locations
    }
    
    fn is_protected_from_callback(&self, location: usize) -> bool {
        // Check for various protection mechanisms
        self.has_reentrancy_lock(location) || 
        self.has_read_lock_or_snapshot(location)
    }
    
    fn has_read_lock_or_snapshot(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 60, self.bytecode.len());
        
        // Look for snapshot pattern: SLOAD into memory
        self.bytecode[location..end]
            .windows(3)
            .any(|w| {
                w[0] == 0x54 && // SLOAD
                w[1] == 0x52    // MSTORE
            })
    }
    
    fn looks_like_view_function(&self, location: usize, _selector: u32) -> bool {
        let end = std::cmp::min(location + 50, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // View functions typically:
        // - Have SLOAD but no SSTORE
        // - Have RETURN
        // - No external CALLs (only STATICCALL ok)
        
        let has_sload = section.iter().any(|&b| b == 0x54);
        let has_sstore = section.iter().any(|&b| b == 0x55);
        let has_call = section.iter().any(|&b| b == 0xf1 || b == 0xf4);
        
        has_sload && !has_sstore && !has_call
    }
    
    fn get_storage_slot_at(&self, location: usize) -> Option<u8> {
        // Look backwards for PUSH of slot number
        let start = location.saturating_sub(5);
        
        for i in start..location {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                return Some(self.bytecode[i+1]);
            }
        }
        
        None
    }
    
    fn reads_slot_after(&self, start: usize, slot: u8, range: usize) -> bool {
        let end = std::cmp::min(start + range, self.bytecode.len());
        
        for i in start..end.saturating_sub(3) {
            if self.bytecode[i] == 0x60 &&
               self.bytecode[i+1] == slot &&
               self.bytecode[i+2] == 0x54 {
                return true;
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
