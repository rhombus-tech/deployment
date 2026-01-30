use serde::{Serialize, Deserialize};

/// Vyper 0.2.15, 0.2.16, 0.3.0 Compiler Bug - Reentrancy in specific patterns
/// This bug affected major protocols like Curve Finance ($70M+ exploited)
/// 
/// The bug occurs when:
/// 1. A contract uses a nonreentrant decorator
/// 2. The function makes an external call
/// 3. The function has multiple entry points (internal calls)
/// 
/// Vyper's reentrancy guard was not properly applied across all code paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VyperCompilerReentrancyVulnerability {
    /// Critical: Vyper 0.2.15/0.2.16 pattern detected
    VyperV2Pattern {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Vyper 0.3.0 pattern detected
    VyperV3Pattern {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Potential vulnerable pattern
    SuspiciousPattern {
        description: String,
        location: usize,
    },
    /// Medium: Vyper-like code without clear protection
    MissingGuard {
        description: String,
        location: usize,
    },
}

pub struct VyperCompilerReentrancyDetector {
    bytecode: Vec<u8>,
}

impl VyperCompilerReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VyperCompilerReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Vyper compiler has specific bytecode patterns
        // Look for the vulnerable reentrancy guard implementation
        
        // Pattern 1: Vyper 0.2.15/0.2.16 - Guard stored at slot 0
        // PUSH1 0x00, SLOAD, PUSH1 0x01, EQ, JUMPI pattern
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for reentrancy guard check pattern
            if self.bytecode[i] == 0x60 &&      // PUSH1
               self.bytecode[i+1] == 0x00 &&    // 0 (storage slot)
               self.bytecode[i+2] == 0x54 &&    // SLOAD
               self.bytecode[i+3] == 0x60 &&    // PUSH1
               self.bytecode[i+4] == 0x01 {     // 1
                
                // This is a reentrancy guard check
                // Now look for external calls after this
                let mut found_call = false;
                let mut guard_set = false;
                
                // Scan forward for CALL and guard update
                for j in i+5..std::cmp::min(i+100, self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 || // CALL
                       self.bytecode[j] == 0xf4 {   // DELEGATECALL
                        found_call = true;
                    }
                    
                    // Check if guard is properly set before call
                    if j > i+5 && 
                       self.bytecode[j] == 0x55 && // SSTORE (setting guard)
                       !found_call {
                        guard_set = true;
                    }
                }
                
                // Vulnerable pattern: Call found but guard not properly set
                if found_call && !guard_set {
                    vulnerabilities.push(VyperCompilerReentrancyVulnerability::VyperV2Pattern {
                        description: "Vyper 0.2.15/0.2.16 reentrancy guard pattern detected - guard not set before external call".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        // Pattern 2: Vyper 0.3.0 - Different guard implementation
        // Look for TSTORE/TLOAD patterns (transient storage) used incorrectly
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x5c || // TLOAD (EIP-1153)
               self.bytecode[i] == 0x5d {  // TSTORE
                
                // Check if this is part of a reentrancy guard
                let has_external_call = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0xf1 || b == 0xf4); // CALL or DELEGATECALL
                
                if has_external_call {
                    vulnerabilities.push(VyperCompilerReentrancyVulnerability::VyperV3Pattern {
                        description: "Vyper 0.3.0 transient storage guard pattern - may be vulnerable".to_string(),
                        location: i,
                        confidence: 0.75,
                    });
                }
            }
        }
        
        // Pattern 3: Multiple entry points without consistent guards
        // Vyper bug: internal function calls bypass the guard
        let mut guard_locations = Vec::new();
        let mut call_locations = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            // Track all reentrancy guard checks
            if self.bytecode[i] == 0x60 &&
               self.bytecode[i+1] == 0x00 &&
               self.bytecode[i+2] == 0x54 {  // SLOAD from slot 0
                guard_locations.push(i);
            }
            
            // Track all external calls
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 {
                call_locations.push(i);
            }
        }
        
        // If we have multiple guards but more calls, suspicious
        if guard_locations.len() < call_locations.len() && 
           guard_locations.len() > 0 &&
           call_locations.len() > 2 {
            vulnerabilities.push(VyperCompilerReentrancyVulnerability::SuspiciousPattern {
                description: format!(
                    "Inconsistent reentrancy protection: {} guards for {} external calls - typical Vyper bug pattern",
                    guard_locations.len(), call_locations.len()
                ),
                location: guard_locations[0],
            });
        }
        
        // Pattern 4: Check for Vyper compiler signature
        // Vyper bytecode often has specific patterns in the constructor
        let has_vyper_signature = self.detect_vyper_compiler_signature();
        
        if has_vyper_signature && call_locations.len() > 0 {
            // Vyper code with external calls but no guards at all
            if guard_locations.is_empty() {
                vulnerabilities.push(VyperCompilerReentrancyVulnerability::MissingGuard {
                    description: "Vyper-compiled contract with external calls but no reentrancy guards detected".to_string(),
                    location: call_locations[0],
                });
            }
        }
        
        vulnerabilities
    }
    
    /// Detect if bytecode was compiled by Vyper
    fn detect_vyper_compiler_signature(&self) -> bool {
        // Vyper has specific patterns in metadata
        // Look for Vyper-specific opcodes sequences
        
        // Vyper often uses specific initialization patterns
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Vyper constructor pattern: CODECOPY with specific offsets
            if self.bytecode[i] == 0x39 && // CODECOPY
               i > 5 {
                // Check for typical Vyper PUSH patterns before CODECOPY
                if self.bytecode[i-5] == 0x60 && // PUSH1
                   self.bytecode[i-3] == 0x60 {  // PUSH1
                    return true;
                }
            }
        }
        
        // Check for Vyper-style function dispatcher
        // Vyper uses a specific pattern for function selection
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 && // PUSH4 (function selector)
               self.bytecode[i+5] == 0x14 && // EQ
               self.bytecode[i+6] == 0x60 && // PUSH1
               self.bytecode[i+8] == 0x57 {  // JUMPI
                return true;
            }
        }
        
        false
    }
}
