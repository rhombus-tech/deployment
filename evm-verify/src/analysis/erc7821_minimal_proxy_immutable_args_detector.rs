use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// ERC-7821 Minimal Proxy with Immutable Args Detector
/// 
/// Detects vulnerabilities in ERC-7821 clone factories that embed immutable arguments
/// in the deployed bytecode, where argument manipulation or validation gaps can occur.
/// 
/// **ERC-7821 Context**:
/// ERC-7821 extends ERC-1167 minimal proxies by appending immutable arguments to the
/// clone bytecode. These args are read via CALLDATALOAD from the clone's own code.
/// 
/// **Attack Patterns**:
/// 1. Immutable arg manipulation during clone deployment
/// 2. Missing validation of immutable args in implementation
/// 3. Arg length mismatch causing out-of-bounds reads
/// 4. Clone with malicious immutable args
/// 5. Implementation assumes args are validated (they're not)
/// 
/// **Detection Strategy**:
/// - Identifies clone factories using CODECOPY to append args
/// - Detects implementations reading args without validation
/// - Flags missing arg length checks
/// - Checks for arg boundary validation
/// - Validates implementation doesn't trust args blindly
pub struct Erc7821MinimalProxyImmutableArgsDetector {
    bytecode: Vec<u8>,
}

impl Erc7821MinimalProxyImmutableArgsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_clone_factory_without_arg_validation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "ERC-7821 clone factory creates proxies with unvalidated immutable args".to_string(),
                operations: Vec::new(),
                remediation: "Validate immutable arguments before deploying clone (length, bounds, constraints)".to_string(),
            });
        }

        if self.has_implementation_trusting_immutable_args() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Implementation reads immutable args without validation - ERC-7821 pattern".to_string(),
                operations: Vec::new(),
                remediation: "Implementation must validate all immutable args, not trust factory".to_string(),
            });
        }

        if self.has_arg_length_mismatch_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Immutable arg length not validated - can cause out-of-bounds reads".to_string(),
                operations: Vec::new(),
                remediation: "Add explicit arg length validation before reading immutable args".to_string(),
            });
        }

        if self.has_codecopy_arg_injection_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "CODECOPY-based arg appending without boundary checks".to_string(),
                operations: Vec::new(),
                remediation: "Validate arg data length and boundaries before CODECOPY".to_string(),
            });
        }

        warnings
    }

    fn has_clone_factory_without_arg_validation(&self) -> bool {
        // Pattern: CREATE/CREATE2 with CODECOPY to append args, but no validation
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0xf0 || self.bytecode[i] == 0xf5 { // CREATE or CREATE2
                let window = &self.bytecode[i.saturating_sub(50)..i+10.min(self.bytecode.len())];
                
                // Check for CODECOPY pattern (appending args to clone bytecode)
                let uses_codecopy = window.windows(20).any(|w| {
                    w.iter().any(|&op| op == 0x39) // CODECOPY
                });
                
                if uses_codecopy {
                    // Check for arg validation before CREATE
                    let validates_args = window.windows(15).any(|w| {
                        // Pattern: check arg length, bounds, or constraints
                        w.iter().any(|&op| op == 0x36) && // CALLDATASIZE (arg length check)
                        w.iter().any(|&op| op == 0x10 || op == 0x11) && // LT/GT
                        w.iter().any(|&op| op == 0xfd) // REVERT if invalid
                    });
                    
                    // Check for arg content validation
                    let validates_content = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x35) && // CALLDATALOAD (read arg)
                        w.iter().any(|&op| op == 0x14) // EQ (validate value)
                    });
                    
                    if !validates_args && !validates_content {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_implementation_trusting_immutable_args(&self) -> bool {
        // Pattern: Reading args from end of code without validation
        // ERC-7821 pattern: CODESIZE - offset to get arg location
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x38 { // CODESIZE (used to locate args)
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check if reading immutable args
                let reads_immutable_args = window.windows(15).any(|w| {
                    // Pattern: CODESIZE, SUB offset, CODECOPY (read args from own code)
                    w.iter().any(|&op| op == 0x38) && // CODESIZE
                    w.iter().any(|&op| op == 0x03) && // SUB (CODESIZE - offset)
                    w.iter().any(|&op| op == 0x39) // CODECOPY (read args)
                });
                
                if reads_immutable_args {
                    // Check for arg validation after reading
                    let validates_after_read = window.windows(20).any(|w| {
                        // Pattern: validate arg value after reading
                        w.iter().any(|&op| op == 0x51) && // MLOAD (read arg from memory)
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (expected value/bound)
                        w.iter().any(|&op| op == 0x10 || op == 0x11 || op == 0x14) // Compare
                    });
                    
                    // Check for arg range validation
                    let validates_range = window.windows(12).any(|w| {
                        w.iter().filter(|&&op| op >= 0x60 && op <= 0x7f).count() >= 2 && // PUSH min/max
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    if !validates_after_read && !validates_range {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_arg_length_mismatch_risk(&self) -> bool {
        // Pattern: Reading args without checking expected length
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x38 { // CODESIZE
                let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                
                // Check if calculating arg location
                let calculates_arg_location = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x38) && // CODESIZE
                    w.iter().any(|&op| op == 0x03) // SUB
                });
                
                if calculates_arg_location {
                    // Check for expected length validation
                    let validates_expected_length = window.windows(12).any(|w| {
                        // Pattern: (CODESIZE - base_code_size) == expected_args_length
                        w.iter().any(|&op| op == 0x03) && // SUB (calculate arg length)
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH expected length
                        w.iter().any(|&op| op == 0x14) // EQ
                    });
                    
                    // Check for minimum length check
                    let has_min_length = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x38) && // CODESIZE
                        w.iter().any(|&op| op == 0x11) && // GT (> minimum)
                        w.iter().any(|&op| op == 0xfd) // REVERT
                    });
                    
                    if !validates_expected_length && !has_min_length {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_codecopy_arg_injection_risk(&self) -> bool {
        // Pattern: CODECOPY without bounds checking
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x39 { // CODECOPY
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check if copying args (involves CODESIZE)
                let copying_args = window.iter().any(|&op| op == 0x38); // CODESIZE
                
                if copying_args {
                    // Check for length validation before copy
                    let validates_length = window.windows(10).any(|w| {
                        // Pattern: validate copy length
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH max length
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    // Check for offset validation
                    let validates_offset = window.windows(8).any(|w| {
                        // Ensure offset + length doesn't exceed CODESIZE
                        w.iter().any(|&op| op == 0x01) && // ADD (offset + length)
                        w.iter().any(|&op| op == 0x10) // LT CODESIZE
                    });
                    
                    if !validates_length && !validates_offset {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erc7821_unvalidated_args() {
        let vulnerable_bytecode = vec![
            0x39, // CODECOPY (append args)
            0xf0, // CREATE (deploy clone - no arg validation!)
        ];

        let detector = Erc7821MinimalProxyImmutableArgsDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("ERC-7821") || w.description.contains("immutable args")));
    }

    #[test]
    fn test_implementation_trusting_args() {
        let vulnerable_bytecode = vec![
            0x38, // CODESIZE (locate args)
            0x03, // SUB (CODESIZE - offset)
            0x39, // CODECOPY (read args - no validation!)
        ];

        let detector = Erc7821MinimalProxyImmutableArgsDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("immutable args") || w.description.contains("validation")));
    }
}
