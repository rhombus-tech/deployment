use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Vyper Mariposa Non-Payable Bypass Detector
/// 
/// Detects the Vyper 0.2.15-0.2.16 and 0.3.0-0.3.3 vulnerability where @nonpayable
/// decorator can be bypassed, allowing ETH to be sent to functions that should reject it.
/// 
/// CVE-2023-XXXXX: Vyper's nonpayable check incorrectly allows msg.value > 0
/// Real Impact: Multiple protocols affected, potential fund loss
pub struct VyperMariposaNonpayableBypassDetector {
    bytecode: Vec<u8>,
}

impl VyperMariposaNonpayableBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // CRITICAL FIX: Only analyze if contract is actually Vyper
        if !self.is_vyper_contract() {
            return findings; // Empty - not a Vyper contract
        }

        // Pattern 1: Missing CALLVALUE check at function entry
        // Vyper should check: CALLVALUE ISZERO followed by conditional jump
        // Bug: Missing or incorrect placement of this check
        if self.has_missing_callvalue_check() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Function lacks proper CALLVALUE validation. Vyper versions 0.2.15-0.2.16 and 0.3.0-0.3.3 have a bug where @nonpayable decorator can be bypassed, allowing ETH transfers to functions that should reject them.".to_string(),
                pc: 0,
                confidence: 0.85,
            });
        }

        // Pattern 2: Vyper-specific bytecode signature with vulnerable pattern
        if self.has_vyper_signature() && self.has_vulnerable_nonpayable_pattern() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Contract appears to be compiled with vulnerable Vyper version containing nonpayable bypass bug. All functions accepting ETH should be audited for unintended value acceptance.".to_string(),
                pc: 0,
                confidence: 0.90,
            });
        }

        // Pattern 3: Function dispatcher with improper CALLVALUE handling
        if let Some(pc) = self.detect_improper_function_dispatcher() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Function dispatcher does not properly validate msg.value before routing to internal functions. This matches the Vyper Mariposa vulnerability pattern.".to_string(),
                pc,
                confidence: 0.80,
            });
        }

        findings
    }

    fn has_missing_callvalue_check(&self) -> bool {
        // Look for functions without proper CALLVALUE -> ISZERO -> JUMPI pattern
        let bytecode = &self.bytecode;
        
        for i in 0..bytecode.len().saturating_sub(20) {
            // Detect function entry (JUMPDEST)
            if bytecode[i] == 0x5B { // JUMPDEST
                // Check next 15 bytes for CALLVALUE check
                let mut has_callvalue = false;
                let mut has_iszero = false;
                let mut has_jumpi = false;

                for j in i+1..std::cmp::min(i+15, bytecode.len()) {
                    if bytecode[j] == 0x34 { has_callvalue = true; } // CALLVALUE
                    if bytecode[j] == 0x15 && has_callvalue { has_iszero = true; } // ISZERO
                    if bytecode[j] == 0x57 && has_iszero { has_jumpi = true; } // JUMPI
                }

                // Function entry without proper CALLVALUE check
                if !has_callvalue || !has_iszero || !has_jumpi {
                    // Check if there's actual logic after JUMPDEST (not just metadata)
                    if i + 5 < bytecode.len() && bytecode[i+1] != 0x00 {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn has_vyper_signature(&self) -> bool {
        // Vyper contracts have distinctive patterns:
        // 1. Free memory pointer initialization (PUSH1 0x40 MSTORE)
        // 2. Specific function dispatcher structure
        // 3. Characteristic CODECOPY patterns
        
        let bytecode = &self.bytecode;
        if bytecode.len() < 10 { return false; }

        // Look for Vyper's characteristic initialization
        // PUSH1 0x80 PUSH1 0x40 MSTORE (free memory pointer)
        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] == 0x60 && bytecode[i+1] == 0x80 &&  // PUSH1 0x80
               bytecode[i+2] == 0x60 && bytecode[i+3] == 0x40 && // PUSH1 0x40
               bytecode[i+4] == 0x52 {  // MSTORE
                return true;
            }
        }

        false
    }

    fn has_vulnerable_nonpayable_pattern(&self) -> bool {
        // Vulnerable Vyper versions have a specific pattern where:
        // 1. Function selector matching happens
        // 2. CALLVALUE check is either missing or incorrectly placed
        // 3. Jump to function happens without proper validation

        let bytecode = &self.bytecode;
        
        for i in 0..bytecode.len().saturating_sub(30) {
            // Look for function selector comparison (EQ after PUSH4)
            if bytecode[i] == 0x63 { // PUSH4 (function selector)
                // Check if followed by EQ
                if i + 6 < bytecode.len() && bytecode[i+5] == 0x14 { // EQ
                    // Check if CALLVALUE validation is present nearby
                    let mut callvalue_check = false;
                    for j in i..std::cmp::min(i+20, bytecode.len()) {
                        if bytecode[j] == 0x34 && // CALLVALUE
                           j+1 < bytecode.len() && bytecode[j+1] == 0x15 { // ISZERO
                            callvalue_check = true;
                            break;
                        }
                    }

                    // If no CALLVALUE check found in function dispatch, vulnerable
                    if !callvalue_check {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn detect_improper_function_dispatcher(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            // Look for function dispatcher pattern:
            // CALLDATALOAD, PUSH29, SHR/DIV (extract function selector)
            if bytecode[i] == 0x35 { // CALLDATALOAD
                // Check for selector extraction pattern
                let mut has_shift = false;
                let mut has_eq = false;
                let mut has_jump = false;

                for j in i+1..std::cmp::min(i+25, bytecode.len()) {
                    if bytecode[j] == 0x1C || bytecode[j] == 0x04 { has_shift = true; } // SHR or DIV
                    if bytecode[j] == 0x14 && has_shift { has_eq = true; } // EQ
                    if bytecode[j] == 0x57 && has_eq { has_jump = true; } // JUMPI
                }

                if has_jump {
                    // Check if CALLVALUE validation exists between selector match and jump
                    let mut callvalue_protected = false;
                    for j in i..std::cmp::min(i+30, bytecode.len()) {
                        if bytecode[j] == 0x34 { // CALLVALUE
                            callvalue_protected = true;
                            break;
                        }
                    }

                    if !callvalue_protected {
                        return Some(i);
                    }
                }
            }
        }

        None
    }

    /// Check if contract is actually compiled with Vyper
    fn is_vyper_contract(&self) -> bool {
        let bytecode = &self.bytecode;
        
        // Check for Solidity-specific patterns that Vyper doesn't have
        let solidity_metadata = b"\xa2\x64\x69\x70\x66\x73\x58";
        if self.contains_pattern(solidity_metadata) {
            return false; // Has Solidity metadata, not Vyper
        }
        
        // Solidity free memory pointer initialization
        let solidity_free_mem = [0x60, 0x80, 0x60, 0x40, 0x52];
        if self.contains_pattern(&solidity_free_mem) {
            return false; // Has Solidity memory init, not Vyper
        }
        
        // Vyper-specific patterns
        let vyper_revert_pattern = [0x60, 0x00, 0x80, 0xFD];
        let has_vyper_pattern = self.contains_pattern(&vyper_revert_pattern);
        
        // Conservative: only return true if we found Vyper patterns
        has_vyper_pattern
    }
    
    /// Helper to check if bytecode contains a specific byte pattern
    fn contains_pattern(&self, pattern: &[u8]) -> bool {
        let bytecode = &self.bytecode;
        if pattern.is_empty() || pattern.len() > bytecode.len() {
            return false;
        }
        
        bytecode.windows(pattern.len())
            .any(|window| window == pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_vyper_pattern() {
        // Simulated vulnerable Vyper bytecode:
        // PUSH1 0x80, PUSH1 0x40, MSTORE (Vyper init)
        // CALLDATALOAD, PUSH29, SHR, PUSH4 (selector), EQ, JUMPI (no CALLVALUE check)
        let bytecode = vec![
            0x60, 0x80, 0x60, 0x40, 0x52, // Vyper init
            0x35, // CALLDATALOAD
            0x7C, // PUSH29
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ...
            0x1C, // SHR
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 (function selector)
            0x14, // EQ
            0x57, // JUMPI (without CALLVALUE check - VULNERABLE)
        ];

        let detector = VyperMariposaNonpayableBypassDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty(), "Should detect vulnerable pattern");
        assert!(findings.iter().any(|f| f.title.contains("Nonpayable")));
    }

    #[test]
    fn test_safe_vyper_pattern() {
        // Safe Vyper bytecode with proper CALLVALUE check
        let bytecode = vec![
            0x60, 0x80, 0x60, 0x40, 0x52, // Vyper init
            0x35, // CALLDATALOAD
            0x7C, // PUSH29
            0x01, 0x00, 0x00, 0x00,
            0x1C, // SHR
            0x34, // CALLVALUE
            0x15, // ISZERO
            0x57, // JUMPI (protected)
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4
            0x14, // EQ
            0x57, // JUMPI
        ];

        let detector = VyperMariposaNonpayableBypassDetector::new(bytecode);
        let findings = detector.detect();

        assert!(findings.is_empty() || findings.iter().all(|f| f.severity != "CRITICAL"));
    }
}
