/// Read-Only Reentrancy Detector
/// Detects Curve-style attacks where view functions return manipulated values during reentrancy

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadOnlyReentrancyVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub view_function_pc: usize,
    pub external_call_pc: usize,
    pub remediation: String,
}

pub struct ReadOnlyReentrancyDetector {
    bytecode: Vec<u8>,
}

impl ReadOnlyReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReadOnlyReentrancyVulnerability> {
        let mut vulns = Vec::new();
        
        // Pattern 1: View function that reads state affected by external calls
        vulns.extend(self.detect_view_state_dependency());
        
        // Pattern 2: Price/ratio calculations without reentrancy protection
        vulns.extend(self.detect_unprotected_getters());
        
        vulns
    }

    /// Detect view functions reading state that can be manipulated mid-call
    fn detect_view_state_dependency(&self) -> Vec<ReadOnlyReentrancyVulnerability> {
        let mut vulns = Vec::new();
        
        // Find STATICCALL (view function) that reads storage
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // STATICCALL = view/pure function
            if opcode == 0xFA {
                // Check if this view function reads storage (SLOAD)
                if self.has_sload_near(pc, 100) {
                    // Check if there are external CALLs that modify same storage
                    if self.has_state_modifying_calls() {
                        vulns.push(ReadOnlyReentrancyVulnerability {
                            severity: SecuritySeverity::Critical,
                            description: "View function reads state that can be manipulated during reentrancy".to_string(),
                            exploit_scenario: "Read-only reentrancy (Curve attack):\n\
                                1. Attacker calls remove_liquidity()\n\
                                2. During callback, reserves temporarily imbalanced\n\
                                3. Attacker calls view function get_virtual_price()\n\
                                4. Returns inflated price due to imbalanced state\n\
                                5. Attacker uses inflated price in another protocol\n\
                                6. Drains value\n\
                                \n\
                                Real exploit: Curve Finance ($60M, July 2023)".to_string(),
                            view_function_pc: pc,
                            external_call_pc: pc,
                            remediation: "Add reentrancy guard to view functions:\n\
                                modifier nonReentrantView() {\n\
                                require(!locked, 'No reentrant view calls');\n\
                                _;\n\
                                }\n\
                                \n\
                                function getPrice() view nonReentrantView returns (uint) {\n\
                                return reserve1 / reserve2;\n\
                                }".to_string(),
                        });
                    }
                }
            }
            
            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }
        
        vulns
    }

    /// Detect price/ratio getters without reentrancy protection
    fn detect_unprotected_getters(&self) -> Vec<ReadOnlyReentrancyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        
        // Pattern: Division operations (price = reserve1 / reserve2) without lock check
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // DIV operation (likely price calculation)
            if opcode == 0x04 {
                // Check if preceded by SLOAD (reading reserves)
                if self.has_sload_before(pc, 50) {
                    // Check if there's no reentrancy lock
                    if !self.has_lock_check_near(pc, 100) {
                        vulns.push(ReadOnlyReentrancyVulnerability {
                            severity: SecuritySeverity::High,
                            description: "Price/ratio calculation without reentrancy protection - can return manipulated values".to_string(),
                            exploit_scenario: "Price manipulation via read-only reentrancy:\n\
                                1. Protocol A trusts Protocol B's getPrice() view function\n\
                                2. Attacker triggers callback in Protocol B\n\
                                3. During callback, calls getPrice()\n\
                                4. Returns manipulated price\n\
                                5. Protocol A makes decision based on fake price\n\
                                6. Attacker profits".to_string(),
                            view_function_pc: pc,
                            external_call_pc: 0,
                            remediation: "Option 1: Add reentrancy lock to view functions\n\
                                Option 2: Snapshot state before external calls\n\
                                Option 3: Use commit-reveal for state changes".to_string(),
                        });
                    }
                }
            }
            
            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }
        
        vulns
    }

    fn has_sload_near(&self, pc: usize, window: usize) -> bool {
        let start = pc.saturating_sub(window);
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[start..end].iter().any(|&b| b == 0x54)
    }

    fn has_sload_before(&self, pc: usize, window: usize) -> bool {
        let start = pc.saturating_sub(window);
        self.bytecode[start..pc].iter().any(|&b| b == 0x54)
    }

    fn has_state_modifying_calls(&self) -> bool {
        self.bytecode.iter().any(|&b| b == 0xF1)  // CALL opcode
    }

    fn has_lock_check_near(&self, pc: usize, window: usize) -> bool {
        let start = pc.saturating_sub(window);
        let end = (pc + window).min(self.bytecode.len());
        // Look for SLOAD followed by ISZERO (checking lock == 0)
        self.bytecode[start..end].windows(2).any(|w| 
            w[0] == 0x54 && w[1] == 0x15
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_vulnerable_view_function() {
        let bytecode = vec![
            0xFA,        // STATICCALL (view function)
            0x60, 0x00,  // PUSH1 0
            0x54,        // SLOAD (reading state)
            0x04,        // DIV (calculating price)
        ];
        let detector = ReadOnlyReentrancyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect read-only reentrancy risk");
    }
}
