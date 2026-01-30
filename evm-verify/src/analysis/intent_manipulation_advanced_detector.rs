use serde::{Serialize, Deserialize};

/// Intent Manipulation Advanced Detection
/// 
/// Intent-based architectures (ERC-7521, CoW Protocol, UniswapX, 1inch Fusion)
/// introduce new attack vectors where malicious solvers/fillers can:
/// 
/// 1. Partially fill intents to cause losses
/// 2. Front-run intent submission
/// 3. Manipulate solver selection
/// 4. Extract MEV through order routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentManipulationAdvancedVulnerability {
    /// Critical: Intent can be partially filled maliciously
    MaliciousPartialFill {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: No solver reputation/bonding system
    UntrustedSolverRisk {
        description: String,
        location: usize,
    },
    /// High: Intent signature can be replayed
    IntentReplayRisk {
        description: String,
        location: usize,
    },
    /// High: Solver can manipulate execution path
    SolverPathManipulation {
        description: String,
        location: usize,
    },
    /// Medium: Missing intent cancellation mechanism
    NoCancellationMechanism {
        description: String,
        location: usize,
    },
}

pub struct IntentManipulationAdvancedDetector {
    bytecode: Vec<u8>,
}

impl IntentManipulationAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<IntentManipulationAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check for intent execution functions
        // executeIntent, fillIntent, settleIntent patterns
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // Check if this looks like an intent execution function
                if self.is_intent_execution_function(i) {
                    // Check for partial fill support
                    let supports_partial = self.supports_partial_fills(i);
                    
                    if supports_partial {
                        // Verify there's slippage protection on partials
                        let has_partial_protection = self.has_partial_fill_protection(i);
                        
                        if !has_partial_protection {
                            vulnerabilities.push(IntentManipulationAdvancedVulnerability::MaliciousPartialFill {
                                description: format!(
                                    "Intent function (0x{:08x}) supports partial fills without protection",
                                    selector
                                ),
                                location: i,
                                confidence: 0.85,
                            });
                        }
                    }
                    
                    // Check for solver verification
                    let verifies_solver = self.verifies_solver_identity(i);
                    
                    if !verifies_solver {
                        vulnerabilities.push(IntentManipulationAdvancedVulnerability::UntrustedSolverRisk {
                            description: "Intent execution without solver verification/bonding".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Check for intent signature verification
        // Must prevent replay attacks
        for i in 0..self.bytecode.len().saturating_sub(80) {
            // Look for ECRECOVER (signature verification)
            if self.bytecode[i] == 0x01 { // Can be part of ecrecover precompile call
                // Check if nonce is used
                let uses_nonce = self.bytecode[i..std::cmp::min(i+80, self.bytecode.len())]
                    .windows(3)
                    .any(|w| {
                        // Look for nonce-like SLOAD and increment
                        w[0] == 0x54 && w[1] == 0x01 && w[2] == 0x55 // SLOAD, ADD, SSTORE
                    });
                
                if !uses_nonce {
                    // Check if deadline is used instead
                    let uses_deadline = self.bytecode[i..std::cmp::min(i+80, self.bytecode.len())]
                        .iter()
                        .any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !uses_deadline {
                        vulnerabilities.push(IntentManipulationAdvancedVulnerability::IntentReplayRisk {
                            description: "Intent signature without nonce or deadline - replay possible".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 3: Check for solver/filler selection mechanism
        for i in 0..self.bytecode.len().saturating_sub(70) {
            // Look for functions that select execution path
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Check if call target comes from calldata (solver-controlled)
                let target_from_calldata = self.bytecode[i.saturating_sub(30)..i]
                    .iter()
                    .any(|&b| b == 0x35); // CALLDATALOAD
                
                if target_from_calldata {
                    // Check if there's whitelist verification
                    let has_whitelist = self.bytecode[i.saturating_sub(40)..i]
                        .windows(5)
                        .any(|w| {
                            // SLOAD (whitelist), EQ, JUMPI pattern
                            w[0] == 0x54 && w[1] == 0x14 && w[2] == 0x57
                        });
                    
                    if !has_whitelist {
                        vulnerabilities.push(IntentManipulationAdvancedVulnerability::SolverPathManipulation {
                            description: "Solver can control execution path without whitelist verification".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for intent cancellation function
        // cancelIntent(), invalidateIntent()
        let has_cancel = self.has_cancellation_mechanism();
        
        if !has_cancel {
            // Check if this is an intent-based system
            let is_intent_system = self.is_intent_based_system();
            
            if is_intent_system {
                vulnerabilities.push(IntentManipulationAdvancedVulnerability::NoCancellationMechanism {
                    description: "Intent system without cancellation mechanism - users can't revoke".to_string(),
                    location: 0,
                });
            }
        }
        
        // Pattern 5: Check for Dutch auction or dynamic pricing
        // These are common in intent systems and can be manipulated
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for time-based price calculations
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let used_in_price_calc = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .windows(4)
                    .any(|w| {
                        // TIMESTAMP -> SUB -> MUL/DIV (decay calculation)
                        w[0] == 0x03 && (w[1] == 0x02 || w[1] == 0x04)
                    });
                
                if used_in_price_calc {
                    // Check for minimum price floor
                    let has_min_price = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .windows(2)
                        .any(|w| w[0] == 0x10 || w[0] == 0x11); // LT or GT
                    
                    if !has_min_price {
                        vulnerabilities.push(IntentManipulationAdvancedVulnerability::SolverPathManipulation {
                            description: "Dutch auction pricing without minimum price floor - solver can wait".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 6: Check for exclusive solver periods
        // Exclusive periods can be gamed
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for solver address comparisons with timestamp
            if self.bytecode[i] == 0x33 { // CALLER
                let checked_with_time = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x42); // TIMESTAMP
                
                if checked_with_time {
                    // This might be an exclusive period
                    // Check if there's fallback to public execution
                    let has_fallback = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                        .windows(3)
                        .filter(|w| w[0] == 0x57) // JUMPI
                        .count() >= 2; // Multiple branches
                    
                    if !has_fallback {
                        vulnerabilities.push(IntentManipulationAdvancedVulnerability::SolverPathManipulation {
                            description: "Exclusive solver period without fallback - can be censored".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_intent_execution_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Intent execution typically has:
        // 1. Signature verification (ecrecover)
        // 2. External calls (to execute the intent)
        // 3. State updates (mark as filled)
        
        let has_sig_verify = section.iter().any(|&b| b == 0x01); // Might be ecrecover
        let has_external_call = section.iter().any(|&b| b == 0xf1 || b == 0xf4);
        let has_state_update = section.iter().any(|&b| b == 0x55);
        
        has_sig_verify && has_external_call && has_state_update
    }
    
    fn supports_partial_fills(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for amount calculations that suggest partial fills
        // Pattern: filledAmount < totalAmount
        self.bytecode[location..end]
            .windows(3)
            .any(|w| {
                // Comparison operations suggesting partial tracking
                (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
                w[1] == 0x57 // JUMPI (conditional on partial)
            })
    }
    
    fn has_partial_fill_protection(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for minimum fill amount checks
        self.bytecode[location..end]
            .windows(4)
            .filter(|w| {
                // PUSH (min amount), LT/GT, JUMPI
                (w[0] >= 0x60 && w[0] <= 0x7f) && 
                (w[2] == 0x10 || w[2] == 0x11) &&
                w[3] == 0x57
            })
            .count() >= 2 // At least 2 amount checks
    }
    
    fn verifies_solver_identity(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for solver verification patterns
        // Either: whitelist check or bonding check
        self.bytecode[location..end]
            .windows(5)
            .any(|w| {
                // CALLER, SLOAD (whitelist/bond), EQ, ISZERO, JUMPI
                w[0] == 0x33 && 
                w[1] == 0x54 && 
                w[2] == 0x14
            })
    }
    
    fn has_cancellation_mechanism(&self) -> bool {
        // Look for cancel/invalidate function patterns
        // These typically set a flag to prevent execution
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                // Check if function sets a cancellation flag
                let sets_cancel_flag = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .windows(4)
                    .any(|w| {
                        // PUSH 1, slot, SSTORE pattern (setting cancelled = true)
                        w[0] == 0x60 && w[1] == 0x01 && w[3] == 0x55
                    });
                
                if sets_cancel_flag {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn is_intent_based_system(&self) -> bool {
        // Heuristic: looks for signature verification + order execution patterns
        
        let has_sig_verify = self.bytecode.iter().any(|&b| b == 0x01);
        
        // Look for order/intent-like data structures
        let has_order_data = self.bytecode
            .windows(3)
            .filter(|w| w[0] == 0x54) // SLOAD
            .count() > 10; // Many storage reads (order data)
        
        has_sig_verify && has_order_data
    }
}
