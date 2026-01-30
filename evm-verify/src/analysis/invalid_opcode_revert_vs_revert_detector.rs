use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidOpcodeVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// INVALID Opcode vs REVERT Detector
///
/// Detects incorrect usage of INVALID (0xfe) opcode versus REVERT (0xfd), which have
/// significantly different gas and state implications.
///
/// Key Differences:
/// - INVALID (0xfe): Consumes all remaining gas, no return data, indicates compiler error
/// - REVERT (0xfd): Refunds unused gas, can return error data, indicates expected failure
/// - INVALID cannot be caught by try/catch, REVERT can be handled
/// - INVALID suggests unreachable code or assertion failure
///
/// Security Implications:
/// - Using INVALID in production logic wastes user gas
/// - INVALID in error handling prevents proper error recovery
/// - Incorrect opcode can bypass error handling in external contracts
/// - DoS attacks via gas exhaustion using INVALID
///
/// Real-World Cases:
/// - Contracts using INVALID for user-triggered errors wasting gas
/// - Error handling broken due to INVALID instead of REVERT
/// - Assertion failures in production causing permanent gas loss
/// - Compiler bugs generating INVALID in wrong contexts
///
/// Detection Strategy:
/// - Identifies INVALID usage in user-facing functions
/// - Detects INVALID after user input validation
/// - Looks for INVALID in error handling paths
/// - Checks for assertion-like patterns using INVALID
/// - Identifies gas exhaustion attack vectors
pub struct InvalidOpcodeRevertVsRevertDetector {
    bytecode: Vec<u8>,
}

impl InvalidOpcodeRevertVsRevertDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InvalidOpcodeVulnerability> {
        self.detect(&self.bytecode)
            .into_iter()
            .map(|finding| InvalidOpcodeVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: INVALID after user input validation (should be REVERT)
            if bytecode[i] == 0xfe {
                if self.has_invalid_after_input_validation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "INVALID opcode misuse: Using INVALID for user input errors wastes all gas, should use REVERT".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: INVALID in public function (non-assertion context)
            if bytecode[i] == 0xfe {
                if self.has_invalid_in_public_function(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Public function INVALID: User-facing function uses INVALID, causing gas exhaustion on expected errors".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: Multiple INVALID opcodes (suspicious pattern)
            if bytecode[i] == 0xfe {
                if self.has_excessive_invalid_opcodes(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Excessive INVALID opcodes: Multiple INVALID usages suggest incorrect error handling or compiler issues".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: REVERT after assertion-like checks (should be INVALID)
            if bytecode[i] == 0xfd {
                if self.has_revert_after_assertion(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "REVERT in assertion: Using REVERT for invariant violations allows bypassing with try/catch".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 5: INVALID with return data setup (impossible)
            if bytecode[i] == 0xfe {
                if self.has_invalid_with_return_data(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "INVALID with return data: Code attempts to return error data with INVALID, which is impossible".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_invalid_after_input_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_calldataload = false;
        let mut has_comparison = false;
        let mut has_jumpi = false;

        // Check for input validation pattern before INVALID
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_calldataload = true, // CALLDATALOAD (input)
                    0x14 | 0x10 | 0x11 => has_comparison = true, // EQ, LT, GT (validation)
                    0x57 => has_jumpi = true, // JUMPI (conditional)
                    _ => {}
                }
            }
        }

        // INVALID after input validation suggests misuse
        has_calldataload && has_comparison && has_jumpi
    }

    fn has_invalid_in_public_function(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut has_function_selector = false;
        let mut has_public_check = false;
        let mut is_assertion = false;

        // Check if this is in a public function
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x63 => {
                        // PUSH4 (function selector)
                        has_function_selector = true;
                    }
                    0x14 => {
                        // EQ (selector comparison)
                        if has_function_selector {
                            has_public_check = true;
                        }
                    }
                    0x15 => {
                        // ISZERO (assertion pattern: require(!condition))
                        is_assertion = true;
                    }
                    _ => {}
                }
            }
        }

        // INVALID in public function without assertion pattern
        has_public_check && !is_assertion
    }

    fn has_excessive_invalid_opcodes(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 100.min(bytecode.len().saturating_sub(pos));
        let lookback = 50.min(pos);
        let mut invalid_count = 1; // Current INVALID

        // Count INVALIDs in surrounding code
        for offset in 1..=lookback {
            if pos >= offset && bytecode[pos - offset] == 0xfe {
                invalid_count += 1;
            }
        }

        for offset in 1..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0xfe {
                invalid_count += 1;
            }
        }

        // More than 3 INVALIDs nearby is suspicious
        invalid_count >= 4
    }

    fn has_revert_after_assertion(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut has_invariant_check = false;
        let mut has_internal_state = false;
        let mut has_overflow_check = false;

        // Check for assertion-like patterns before REVERT
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => has_internal_state = true, // SLOAD (internal state check)
                    0x10 | 0x11 => {
                        // LT, GT (overflow/underflow checks)
                        if has_internal_state {
                            has_overflow_check = true;
                        }
                    }
                    0x15 => {
                        // ISZERO (assertion: require(!condition))
                        if has_internal_state {
                            has_invariant_check = true;
                        }
                    }
                    0x35 => {
                        // CALLDATALOAD suggests user input, not assertion
                        has_invariant_check = false;
                    }
                    _ => {}
                }
            }
        }

        // REVERT used for invariant/assertion (should be INVALID)
        has_invariant_check && has_internal_state && !has_overflow_check
    }

    fn has_invalid_with_return_data(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let mut has_mstore = false;
        let mut has_error_selector = false;
        let mut mstore_count = 0;

        // Check for error data construction before INVALID
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x52 => {
                        has_mstore = true;
                        mstore_count += 1;
                    }
                    0x63 => {
                        // PUSH4 (error selector)
                        if pos >= offset + 4 {
                            // Common error selectors start with 0x08c379a0 (Error(string))
                            has_error_selector = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Attempted error data return before INVALID (impossible)
        has_mstore && has_error_selector && mstore_count >= 2
    }
}
