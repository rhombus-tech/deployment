use serde::{Deserialize, Serialize};

/// EIP-1271 Recursive Validation DoS Detection
/// 
/// Detects recursive signature validation vulnerabilities:
/// 1. isValidSignature can call itself recursively
/// 2. No recursion depth limit
/// 3. Circular validation dependencies
/// 4. Reentrancy in validation logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip1271RecursiveValidationVulnerability {
    /// Critical: Recursive isValidSignature call
    RecursiveValidationCall {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: No recursion depth limit
    NoRecursionDepthLimit {
        description: String,
        location: usize,
    },
    /// High: Circular validation between contracts
    CircularValidationDependency {
        description: String,
        validator_a: usize,
        validator_b: usize,
    },
    /// Medium: External call in validation without reentrancy guard
    ValidationReentrancyRisk {
        description: String,
        location: usize,
    },
}

pub struct Eip1271RecursiveValidationDetector {
    bytecode: Vec<u8>,
}

impl Eip1271RecursiveValidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip1271RecursiveValidationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Find all isValidSignature implementations
        let validation_functions = self.find_is_valid_signature_functions();
        
        for location in &validation_functions {
            // Pattern 1: Check for recursive calls
            let has_recursive_call = self.has_recursive_validation_call(*location, location + 200);
            
            if has_recursive_call {
                vulnerabilities.push(Eip1271RecursiveValidationVulnerability::RecursiveValidationCall {
                    description: "isValidSignature can recursively call itself or similar validators".to_string(),
                    location: *location,
                    confidence: 0.90,
                });
            }
            
            // Pattern 2: Check for recursion depth tracking
            let has_depth_limit = self.has_recursion_depth_limit(*location, location + 200);
            
            if !has_depth_limit && has_recursive_call {
                vulnerabilities.push(Eip1271RecursiveValidationVulnerability::NoRecursionDepthLimit {
                    description: "No recursion depth limit enforced in signature validation".to_string(),
                    location: *location,
                });
            }
            
            // Pattern 3: Reentrancy risk in validation
            let has_reentrancy_risk = self.has_validation_reentrancy_risk(*location, location + 200);
            
            if has_reentrancy_risk {
                vulnerabilities.push(Eip1271RecursiveValidationVulnerability::ValidationReentrancyRisk {
                    description: "External call in validation without reentrancy protection".to_string(),
                    location: *location,
                });
            }
        }
        
        // Pattern 4: Circular validation dependencies
        if validation_functions.len() >= 2 {
            for i in 0..validation_functions.len() {
                for j in i + 1..validation_functions.len() {
                    let circular = self.has_circular_validation(
                        validation_functions[i],
                        validation_functions[j]
                    );
                    
                    if circular {
                        vulnerabilities.push(Eip1271RecursiveValidationVulnerability::CircularValidationDependency {
                            description: "Circular signature validation between contracts".to_string(),
                            validator_a: validation_functions[i],
                            validator_b: validation_functions[j],
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_is_valid_signature_functions(&self) -> Vec<usize> {
        let mut functions = Vec::new();
        
        // EIP-1271 isValidSignature selector: 0x1626ba7e
        // Also check for: 0x20c13b0b (old EIP-1271)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 4 < self.bytecode.len() {
                    let selector = &self.bytecode[i + 1..i + 5];
                    
                    if matches!(selector, 
                        [0x16, 0x26, 0xba, 0x7e] | // isValidSignature(bytes32,bytes)
                        [0x20, 0xc1, 0x3b, 0x0b]   // isValidSignature(bytes,bytes) old
                    ) {
                        functions.push(i);
                    }
                }
            }
        }
        
        functions
    }
    
    fn has_recursive_validation_call(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for:
        // 1. STATICCALL or CALL with isValidSignature selector
        // 2. Or ADDRESS + STATICCALL (calling self)
        
        let has_validation_selector = self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w[0] == 0x63 && // PUSH4
                w[1] == 0x16 && w[2] == 0x26 && w[3] == 0xba // isValidSignature
            });
        
        let has_external_call = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xfa || b == 0xf1); // STATICCALL or CALL
        
        let calls_self = self.bytecode[start..range_end]
            .windows(2)
            .any(|w| w[0] == 0x30 && w[1] == 0xfa); // ADDRESS + STATICCALL
        
        (has_validation_selector && has_external_call) || calls_self
    }
    
    fn has_recursion_depth_limit(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Depth limit pattern:
        // 1. SLOAD depth counter
        // 2. Increment depth
        // 3. Check depth < MAX
        // 4. REVERT if too deep
        // 5. Decrement on return
        
        let has_depth_load = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x60 && // PUSH1 (depth slot)
                w[2] == 0x54    // SLOAD
            });
        
        let has_depth_check = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x10 && // LT
                w[1] == 0x15 && // ISZERO
                w[2] == 0xfd    // REVERT
            });
        
        has_depth_load && has_depth_check
    }
    
    fn has_validation_reentrancy_risk(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Reentrancy risk if:
        // 1. Has external call
        // 2. No reentrancy guard
        // 3. State modified after external call
        
        let has_external_call = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xfa || b == 0xf1);
        
        if !has_external_call {
            return false;
        }
        
        // Find external call location
        let call_location = self.bytecode[start..range_end]
            .iter()
            .position(|&b| b == 0xfa || b == 0xf1)
            .map(|pos| start + pos);
        
        if let Some(call_loc) = call_location {
            // Check for reentrancy guard
            let has_guard = self.bytecode[start..call_loc]
                .windows(5)
                .any(|w| {
                    w.iter().any(|&b| b == 0x54) && // SLOAD
                    w.iter().any(|&b| b == 0x15) && // ISZERO
                    w.iter().any(|&b| b == 0xfd)    // REVERT
                });
            
            // Check for state modification after call
            let has_post_call_state_mod = self.bytecode[call_loc..range_end]
                .iter()
                .any(|&b| b == 0x55); // SSTORE
            
            !has_guard && has_post_call_state_mod
        } else {
            false
        }
    }
    
    fn has_circular_validation(&self, validator_a: usize, validator_b: usize) -> bool {
        let range_a_end = (validator_a + 200).min(self.bytecode.len());
        let range_b_end = (validator_b + 200).min(self.bytecode.len());
        
        // Check if validator_a calls validator_b AND validator_b calls validator_a
        
        let a_calls_b = self.bytecode[validator_a..range_a_end]
            .windows(30)
            .any(|w| {
                w.iter().any(|&b| b == 0xfa) && // STATICCALL
                w.iter().filter(|&&b| b == 0x63).count() > 0 // Function selector
            });
        
        let b_calls_a = self.bytecode[validator_b..range_b_end]
            .windows(30)
            .any(|w| {
                w.iter().any(|&b| b == 0xfa) &&
                w.iter().filter(|&&b| b == 0x63).count() > 0
            });
        
        a_calls_b && b_calls_a
    }
}
