use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Log Poisoning Attack Detector
///
/// Detects malicious log emission patterns designed to poison off-chain
/// indexers and event listeners with fake or misleading events.
///
/// Attack Vector: Attacker emits events that mimic legitimate protocol events
/// Impact: Fake transfers, false positives in indexers, UI spoofing
/// Risk: Critical for protocols relying on events for state tracking
///
/// Detection Strategy:
/// - Identifies unrestricted LOG operations callable by anyone
/// - Detects events emitted without proper access control
/// - Checks for events that can be triggered with arbitrary parameters
/// - Looks for missing sender validation in event emission
pub struct LogPoisoningAttackDetector;

impl LogPoisoningAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: LOG operation without access control
            if self.is_log_operation(bytecode[i]) {
                if self.has_unrestricted_log_emission(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unrestricted event emission detected: Anyone can emit events, enabling log poisoning attacks".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: Transfer-like event without balance check
            if self.is_log_operation(bytecode[i]) {
                if self.has_fake_transfer_event_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Transfer event emitted without balance verification: Attacker could emit fake Transfer events".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 3: Event with user-controlled parameters
            if self.is_log_operation(bytecode[i]) {
                if self.has_user_controlled_event_data(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Event with user-controlled data: Attacker can inject arbitrary event parameters".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            // Pattern 4: Event emission before state changes
            if self.is_log_operation(bytecode[i]) {
                if self.has_event_before_state_update(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Event emitted before state change: Could emit event even if transaction fails".to_string(),
                        pc: i,
                        confidence: 0.79,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn is_log_operation(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0 through LOG4
    }

    fn has_unrestricted_log_emission(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut has_caller_check = false;
        let mut has_revert = false;
        let mut has_access_control = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x33 => {
                        // CALLER - check if followed by comparison
                        if offset <= 5 || pos >= offset - 5 {
                            for check_offset in 1..5 {
                                if pos >= offset.saturating_sub(check_offset) {
                                    match bytecode[pos - offset + check_offset] {
                                        0x14 => has_caller_check = true, // EQ
                                        0xfd => has_revert = true, // REVERT
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    0x54 => {
                        // SLOAD - loading owner/admin
                        has_access_control = true;
                    }
                    0xfd => has_revert = true, // REVERT
                    _ => {}
                }
            }
        }

        // No access control found before LOG operation
        !has_caller_check && !has_access_control && !has_revert
    }

    fn has_fake_transfer_event_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 45.min(pos);
        let mut has_from_address = false;
        let mut has_to_address = false;
        let mut has_amount = false;
        let mut has_balance_check = false;
        let mut has_sload = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x73 => {
                        // PUSH20 (address)
                        if !has_from_address {
                            has_from_address = true;
                        } else {
                            has_to_address = true;
                        }
                    }
                    0x35 => has_amount = true, // CALLDATALOAD (user input)
                    0x54 => has_sload = true, // SLOAD (balance check)
                    0x11 | 0x10 => {
                        // GT/LT (comparison for balance check)
                        if has_sload {
                            has_balance_check = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Transfer event pattern without balance verification
        has_from_address && has_to_address && has_amount && !has_balance_check
    }

    fn has_user_controlled_event_data(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut calldataload_count = 0;
        let mut has_validation = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => calldataload_count += 1, // CALLDATALOAD
                    0x15 => has_validation = true, // ISZERO (validation check)
                    0xfd => has_validation = true, // REVERT
                    0x10 | 0x11 | 0x12 => has_validation = true, // LT/GT/SLT
                    _ => {}
                }
            }
        }

        // Multiple user inputs used in event without validation
        calldataload_count >= 2 && !has_validation
    }

    fn has_event_before_state_update(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sstore_after = false;
        let mut has_call_after = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x55 => has_sstore_after = true, // SSTORE (state update after event)
                    0xf1 | 0xf2 | 0xf4 => has_call_after = true, // CALL/CALLCODE/DELEGATECALL
                    _ => {}
                }
            }
        }

        // Event emitted but critical operations happen after
        // (event might be emitted even if transaction reverts later)
        !has_sstore_after && !has_call_after
    }
}
