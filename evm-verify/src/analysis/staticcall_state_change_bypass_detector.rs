use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticCallBypassVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// STATICCALL State Change Bypass Detector
///
/// Detects vulnerabilities where STATICCALL is used with the assumption of read-only behavior,
/// but state changes can still occur through indirect mechanisms or implementation bugs.
///
/// Bypass Mechanisms:
/// - LOG operations are allowed in STATICCALL (not considered state changes by EVM)
/// - Reentrancy through STATICCALL to contracts with CALL can modify state
/// - Gas-based side channels can leak information about state
/// - STATICCALL to precompiles that have bugs
/// - View functions that aren't truly read-only
///
/// Real-World Cases:
/// - Price oracle manipulation through LOG-based attacks
/// - Read-only reentrancy in Curve and other DeFi protocols
/// - STATICCALL used for security but bypassed via logs
/// - View functions with side effects in certain EVM implementations
///
/// Detection Strategy:
/// - Identifies STATICCALL followed by state-changing operations
/// - Detects LOG operations within STATICCALL context
/// - Looks for reentrancy patterns using STATICCALL
/// - Checks for view functions that aren't truly read-only
/// - Identifies gas-based side channel vulnerabilities
pub struct StaticcallStateChangeBypassDetector {
    bytecode: Vec<u8>,
}

impl StaticcallStateChangeBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StaticCallBypassVulnerability> {
        self.detect(&self.bytecode)
            .into_iter()
            .map(|finding| StaticCallBypassVulnerability {
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
            // Pattern 1: STATICCALL followed by state changes (read-only reentrancy)
            if bytecode[i] == 0xfa {
                if self.has_staticcall_reentrancy_bypass(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "STATICCALL reentrancy bypass: Read-only call followed by state changes enables reentrancy attacks".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 2: LOG operations in STATICCALL context (events as state)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_log_in_staticcall_context(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "LOG in STATICCALL context: Events emitted during 'read-only' call can be exploited for oracle manipulation".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: STATICCALL with return data used for state changes
            if bytecode[i] == 0xfa {
                if self.has_staticcall_return_data_state_change(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "STATICCALL return data state change: Read-only call result directly controls state modifications".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 4: View function with external calls (not truly read-only)
            if bytecode[i] == 0xf1 {
                if self.has_view_function_with_external_calls(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "View function external call: Function marked view/pure contains external calls that may have side effects".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 5: Gas-based side channel in STATICCALL
            if bytecode[i] == 0xfa {
                if self.has_gas_side_channel_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "STATICCALL gas side channel: Gas consumption patterns can leak state information from 'read-only' calls".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_staticcall_reentrancy_bypass(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 50.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;
        let mut has_balance_check = false;
        let mut has_comparison = false;

        // Check operations after STATICCALL
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true, // SLOAD (reading state)
                    0x55 => has_sstore = true, // SSTORE (writing state)
                    0x47 => has_balance_check = true, // SELFBALANCE
                    0x14 | 0x10 | 0x11 => has_comparison = true, // EQ, LT, GT
                    _ => {}
                }
            }
        }

        // STATICCALL followed by state reads and writes (read-only reentrancy)
        has_sload && has_sstore && (has_balance_check || has_comparison)
    }

    fn has_log_in_staticcall_context(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_staticcall_before = false;
        let mut has_function_dispatch = false;
        let mut no_state_changes = true;

        // Check if this LOG is in a STATICCALL context (view function)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xfa => has_staticcall_before = true, // STATICCALL
                    0x55 => no_state_changes = false, // SSTORE (not in view function)
                    0x14 => {
                        // EQ in function selector comparison
                        if pos >= offset + 5 {
                            has_function_dispatch = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // LOG in view function context
        (has_staticcall_before || has_function_dispatch) && no_state_changes
    }

    fn has_staticcall_return_data_state_change(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 45.min(bytecode.len().saturating_sub(pos));
        let mut has_returndatacopy = false;
        let mut has_sstore = false;
        let mut return_data_used = false;
        let mut mload_count = 0;

        // Check if return data from STATICCALL is used for state changes
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x3e => has_returndatacopy = true, // RETURNDATACOPY
                    0x51 => {
                        // MLOAD (loading return data)
                        if has_returndatacopy {
                            return_data_used = true;
                            mload_count += 1;
                        }
                    }
                    0x55 => {
                        // SSTORE (state change)
                        if return_data_used {
                            has_sstore = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Return data from STATICCALL directly controls state
        has_returndatacopy && return_data_used && has_sstore && mload_count >= 1
    }

    fn has_view_function_with_external_calls(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut is_view_function = true;
        let mut has_staticcall = false;
        let mut has_external_target = false;

        // Check if this is in a view function (no SSTORE operations)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x55 => is_view_function = false, // SSTORE (not view)
                    0xfa => has_staticcall = true, // STATICCALL nearby
                    0x35 => has_external_target = true, // CALLDATALOAD (external address)
                    _ => {}
                }
            }
        }

        // Check for return after CALL
        let mut has_return = false;
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xf3 {
                    has_return = true;
                    break;
                }
            }
        }

        // CALL in view function context
        is_view_function && has_external_target && has_return && !has_staticcall
    }

    fn has_gas_side_channel_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let window = 40.min(bytecode.len().saturating_sub(pos));
        
        let mut has_gas_check = false;
        let mut has_conditional = false;
        let mut has_loop = false;
        let mut gas_operations = 0;

        // Check for GAS operations before STATICCALL
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x5a => {
                        gas_operations += 1;
                        has_gas_check = true;
                    }
                    0x57 => has_conditional = true, // JUMPI
                    _ => {}
                }
            }
        }

        // Check for gas-dependent logic after STATICCALL
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x5a => gas_operations += 1, // GAS
                    0x57 => {
                        // JUMPI after gas check
                        if has_gas_check {
                            has_loop = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Multiple GAS operations with conditionals (side channel)
        gas_operations >= 2 && has_conditional && has_loop
    }

    fn is_log_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0-LOG4
    }
}
