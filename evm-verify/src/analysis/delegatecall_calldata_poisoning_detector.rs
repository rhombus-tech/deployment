use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// DELEGATECALL Calldata Poisoning Detector
///
/// Detects vulnerabilities where DELEGATECALL forwards untrusted calldata that can
/// poison the execution context, leading to unauthorized state changes or logic bypasses.
///
/// Attack Vectors:
/// - Forwarding raw calldata to implementation without validation
/// - Function selector collision via poisoned calldata
/// - Storage slot manipulation through crafted calldata
/// - Unauthorized function execution via selector crafting
/// - Context confusion in proxy patterns
///
/// Real-World Cases:
/// - Parity Wallet hack: DELEGATECALL with arbitrary calldata
/// - Multiple proxy contracts exploited via calldata manipulation
/// - Initialization function called multiple times
/// - Access control bypass via poisoned selectors
///
/// Detection Strategy:
/// - Identifies DELEGATECALL with raw calldata forwarding
/// - Detects missing function selector validation
/// - Looks for unprotected implementation calls
/// - Checks for calldata passthrough without sanitization
/// - Identifies proxy patterns without proper guards
pub struct DelegatecallCalldataPoisoningDetector;

impl DelegatecallCalldataPoisoningDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: DELEGATECALL with full calldata forward
            if bytecode[i] == 0xf4 {
                if self.has_full_calldata_forward(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "DELEGATECALL calldata poisoning: Forwarding entire calldata to DELEGATECALL enables arbitrary function execution".to_string(),
                        pc: i,
                        confidence: 0.90,
                    });
                }
            }

            // Pattern 2: DELEGATECALL without selector validation
            if bytecode[i] == 0xf4 {
                if self.has_unvalidated_selector(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unvalidated DELEGATECALL selector: No function selector whitelist, enables poisoned calldata attacks".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 3: Proxy fallback with direct passthrough
            if bytecode[i] == 0xf4 {
                if self.has_unsafe_proxy_fallback(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unsafe proxy fallback: Fallback directly forwards to DELEGATECALL without validation".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 4: DELEGATECALL with user-controlled target
            if bytecode[i] == 0xf4 {
                if self.has_user_controlled_delegatecall(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "User-controlled DELEGATECALL: Target address from calldata enables complete contract takeover".to_string(),
                        pc: i,
                        confidence: 0.91,
                    });
                }
            }

            // Pattern 5: DELEGATECALL in loop with calldata
            if bytecode[i] == 0xf4 {
                if self.has_loop_delegatecall_with_calldata(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Loop DELEGATECALL poisoning: Multiple delegatecalls with incrementing calldata offsets vulnerable to poisoning".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_full_calldata_forward(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut has_calldatasize = false;
        let mut has_calldatacopy = false;
        let mut copy_from_zero = false;

        // Check for full calldata copying pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x36 => has_calldatasize = true, // CALLDATASIZE (full size)
                    0x37 => has_calldatacopy = true, // CALLDATACOPY
                    0x60 => {
                        // PUSH1 0 (copy from offset 0)
                        if pos >= offset + 1 && bytecode.get(pos - offset + 1) == Some(&0x00) {
                            copy_from_zero = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Full calldata forwarded to DELEGATECALL
        has_calldatasize && has_calldatacopy && copy_from_zero
    }

    fn has_unvalidated_selector(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_selector_load = false;
        let mut has_selector_check = false;
        let mut has_whitelist = false;

        // Check for selector validation
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => {
                        // CALLDATALOAD at offset 0 (selector)
                        if pos >= offset + 2 {
                            if bytecode.get(pos - offset - 1) == Some(&0x60) 
                                && bytecode.get(pos - offset) == Some(&0x00) {
                                has_selector_load = true;
                            }
                        }
                    }
                    0x14 => has_selector_check = true, // EQ (selector comparison)
                    0x63 => has_whitelist = true, // PUSH4 (allowed selector)
                    0xfd => {
                        // REVERT (reject invalid selectors)
                        if has_selector_check {
                            has_whitelist = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Selector loaded but not validated against whitelist
        has_selector_load && !has_whitelist
    }

    fn has_unsafe_proxy_fallback(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut is_fallback = false;
        let mut has_implementation_load = false;
        let mut has_access_check = false;

        // Check for fallback proxy pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x36 => is_fallback = true, // CALLDATASIZE (fallback check)
                    0x54 => has_implementation_load = true, // SLOAD (implementation address)
                    0x33 => has_access_check = true, // CALLER (access control)
                    0x14 => {
                        // EQ (checking caller)
                        if has_access_check {
                            has_access_check = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Fallback with DELEGATECALL but no access control
        is_fallback && has_implementation_load && !has_access_check
    }

    fn has_user_controlled_delegatecall(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut target_from_calldata = false;
        let mut target_from_storage = false;
        let mut has_address_validation = false;

        // Check source of DELEGATECALL target address
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => target_from_calldata = true, // CALLDATALOAD (user input!)
                    0x54 => target_from_storage = true, // SLOAD (potentially safer)
                    0x3b => has_address_validation = true, // EXTCODESIZE (checking if contract)
                    0x14 => has_address_validation = true, // EQ (whitelist check)
                    _ => {}
                }
            }
        }

        // DELEGATECALL target from calldata without validation
        target_from_calldata && !has_address_validation && !target_from_storage
    }

    fn has_loop_delegatecall_with_calldata(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut in_loop = false;
        let mut has_calldata_offset_increment = false;
        let mut has_calldatacopy = false;
        let mut has_counter = false;

        // Check for loop with calldata operations
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => in_loop = true, // JUMPI (loop)
                    0x37 => has_calldatacopy = true, // CALLDATACOPY
                    0x01 => {
                        // ADD (offset increment)
                        if has_calldatacopy {
                            has_calldata_offset_increment = true;
                        }
                    }
                    0x03 => has_counter = true, // SUB (loop counter)
                    _ => {}
                }
            }
        }

        // Multiple DELEGATECALLs in loop with calldata
        in_loop && has_calldata_offset_increment && has_calldatacopy && has_counter
    }
}
