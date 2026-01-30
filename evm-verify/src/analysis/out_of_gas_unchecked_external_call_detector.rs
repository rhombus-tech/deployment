use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutOfGasUncheckedVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Out of Gas Unchecked External Call Detector
///
/// Detects external calls that can silently fail due to out-of-gas conditions without
/// proper return value checking, leading to critical security vulnerabilities.
///
/// Vulnerability Scenarios:
/// - External call runs out of gas but contract continues execution
/// - Return value not checked, assuming success
/// - State changes committed despite call failure
/// - Reentrancy guards bypassed via out-of-gas
/// - Complex calls with insufficient gas forwarding
///
/// Real-World Cases:
/// - King of the Ether: unchecked send() led to stuck contract
/// - Multiple DeFi protocols lost funds due to unchecked calls
/// - ERC20 transfer failures not detected
/// - Cross-contract calls silently failing
///
/// Detection Strategy:
/// - Identifies CALL/STATICCALL/DELEGATECALL without return checks
/// - Detects insufficient gas forwarding patterns
/// - Looks for state changes after unchecked calls
/// - Checks for missing success validation
/// - Identifies dangerous call patterns in loops
pub struct OutOfGasUncheckedExternalCallDetector;

impl OutOfGasUncheckedExternalCallDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: CALL without return value check
            if bytecode[i] == 0xf1 {
                if self.has_unchecked_call_return(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unchecked external call: CALL return value not validated, can fail silently due to out-of-gas".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 2: STATICCALL without return check (read operations)
            if bytecode[i] == 0xfa {
                if self.has_unchecked_staticcall_return(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unchecked STATICCALL: View/pure call can fail silently, leading to incorrect data assumptions".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: DELEGATECALL without return check (critical)
            if bytecode[i] == 0xf4 {
                if self.has_unchecked_delegatecall_return(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unchecked DELEGATECALL: Critical delegatecall without return validation can corrupt state on failure".to_string(),
                        pc: i,
                        confidence: 0.90,
                    });
                }
            }

            // Pattern 4: Call with state change after (dangerous pattern)
            if bytecode[i] == 0xf1 || bytecode[i] == 0xfa || bytecode[i] == 0xf4 {
                if self.has_state_change_after_unchecked_call(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "State change after unchecked call: Contract modifies state assuming call success without validation".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 5: Call in loop without gas consideration
            if bytecode[i] == 0xf1 {
                if self.has_call_in_loop_without_gas_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Loop call without gas check: Multiple external calls in loop can run out of gas, causing partial failures".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<OutOfGasUncheckedVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| OutOfGasUncheckedVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_unchecked_call_return(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 10.min(bytecode.len().saturating_sub(pos));
        let mut return_checked = false;
        let mut return_popped = false;

        // Check what happens to return value
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 => return_checked = true, // ISZERO (checking success)
                    0x57 => return_checked = true, // JUMPI (conditional on return)
                    0x50 => {
                        // POP (discarding return value!)
                        return_popped = true;
                        break;
                    }
                    0xfd => return_checked = true, // REVERT on failure
                    _ => {}
                }
            }
        }

        // Return value not checked or explicitly discarded
        !return_checked || return_popped
    }

    fn has_unchecked_staticcall_return(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 12.min(bytecode.len().saturating_sub(pos));
        let mut return_checked = false;
        let mut has_returndatacopy = false;

        // Check if return value is validated
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 => return_checked = true, // ISZERO
                    0x57 => return_checked = true, // JUMPI
                    0x3e => has_returndatacopy = true, // RETURNDATACOPY (using data)
                    0x50 => return !has_returndatacopy, // POP after RETURNDATACOPY is ok
                    _ => {}
                }
            }
        }

        // STATICCALL data used without checking success
        !return_checked && has_returndatacopy
    }

    fn has_unchecked_delegatecall_return(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 15.min(bytecode.len().saturating_sub(pos));
        let mut return_checked = false;
        let mut has_revert = false;

        // DELEGATECALL should always check return
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 => return_checked = true, // ISZERO
                    0x57 => return_checked = true, // JUMPI
                    0xfd => has_revert = true, // REVERT
                    0x50 => return true, // POP on DELEGATECALL is always bad
                    _ => {}
                }
            }
        }

        // DELEGATECALL without proper validation
        !return_checked || !has_revert
    }

    fn has_state_change_after_unchecked_call(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut return_checked = false;
        let mut has_state_change = false;
        let mut check_before_state = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 | 0x57 => {
                        return_checked = true;
                        check_before_state = !has_state_change;
                    }
                    0x55 => has_state_change = true, // SSTORE
                    0xf1 | 0xfa => has_state_change = true, // Additional calls
                    _ => {}
                }
            }
        }

        // State change without prior return check
        has_state_change && (!return_checked || !check_before_state)
    }

    fn has_call_in_loop_without_gas_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut in_loop = false;
        let mut has_gas_check = false;
        let mut has_counter = false;

        // Check for loop context
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => in_loop = true, // JUMPI (loop)
                    0x5a => has_gas_check = true, // GAS (checking remaining)
                    0x01 | 0x03 => has_counter = true, // ADD, SUB (loop counter)
                    _ => {}
                }
            }
        }

        // Call in loop without gas consideration
        in_loop && has_counter && !has_gas_check
    }
}
