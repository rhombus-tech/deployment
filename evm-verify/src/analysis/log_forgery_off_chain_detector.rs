use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Log Forgery Off-Chain Detector
///
/// Detects vulnerabilities where event logs can be forged or manipulated to deceive
/// off-chain systems that rely on event data for state tracking or business logic.
///
/// Attack Vectors:
/// - Emitting fake events without corresponding state changes
/// - Event parameter manipulation to fake transactions
/// - Replay of legitimate events in malicious contexts
/// - Off-chain indexer poisoning via crafted events
/// - Cross-contract event spoofing
///
/// Real-World Cases:
/// - Off-chain systems trusting events without on-chain verification
/// - Token transfer events without actual transfers
/// - NFT sale events for non-existent transactions
/// - DeFi protocol events misleading analytics platforms
///
/// Detection Strategy:
/// - Identifies LOG operations without preceding state changes
/// - Detects events emitted in view/pure functions
/// - Looks for events without corresponding external calls
/// - Checks for event emissions without value transfers
/// - Identifies suspicious event-only functions
pub struct LogForgeryOffChainDetector;

impl LogForgeryOffChainDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: LOG without state change (fake event)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_log_without_state_change(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Log forgery: Event emitted without corresponding state change, can deceive off-chain systems".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: Transfer event without actual transfer
            if self.is_log_opcode(bytecode[i]) {
                if self.has_transfer_event_without_call(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Fake transfer event: Transfer event emitted without actual CALL or value transfer".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 3: Event in STATICCALL context (view function)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_event_in_view_context(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Event in view function: Event emission in read-only context may indicate forgery attempt".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: Event-only function (no side effects)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_event_only_function(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Event-only function: Function only emits events without state changes, likely forgery".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 5: Multiple similar events (spam/poisoning)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_event_spam_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Event spam pattern: Multiple identical events may poison off-chain indexers".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_log_without_state_change(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let window = 20.min(bytecode.len().saturating_sub(pos));
        
        let mut has_sstore = false;
        let mut has_call = false;
        let mut has_sload_only = false;

        // Check for state changes before event
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x55 => has_sstore = true, // SSTORE
                    0xf1 | 0xfa => has_call = true, // CALL, STATICCALL
                    0x54 => has_sload_only = true, // SLOAD (read-only)
                    _ => {}
                }
            }
        }

        // Check after event too
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x55 => has_sstore = true,
                    0xf1 => has_call = true,
                    _ => {}
                }
            }
        }

        // Event without state modification
        !has_sstore && !has_call && has_sload_only
    }

    fn has_transfer_event_without_call(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut has_transfer_topic = false;
        let mut has_value_param = false;
        let mut has_call = false;
        let mut has_callvalue = false;

        // Check for Transfer event pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x7f => {
                        // PUSH32 - could be Transfer event topic
                        // keccak256("Transfer(address,address,uint256)")
                        if pos >= offset + 32 {
                            let data = &bytecode[pos - offset + 1..pos - offset + 33];
                            // Transfer topic hash starts with 0xddf252ad...
                            if data[0] == 0xdd && data[1] == 0xf2 {
                                has_transfer_topic = true;
                            }
                        }
                    }
                    0x60..=0x7f => has_value_param = true, // Value being transferred
                    0xf1 => has_call = true, // CALL
                    0x34 => has_callvalue = true, // CALLVALUE
                    _ => {}
                }
            }
        }

        // Transfer event without actual transfer
        has_transfer_topic && has_value_param && !has_call && !has_callvalue
    }

    fn has_event_in_view_context(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut in_view_function = true;
        let mut has_staticcall = false;

        // Check if this is in view/pure context (no SSTORE)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x55 => in_view_function = false, // SSTORE (not view)
                    0xfa => has_staticcall = true, // STATICCALL context
                    0xf1 | 0xf4 => in_view_function = false, // State-changing calls
                    _ => {}
                }
            }
        }

        // Event in view/pure function or STATICCALL
        in_view_function || has_staticcall
    }

    fn has_event_only_function(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 60.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut has_function_entry = false;
        let mut has_sstore = false;
        let mut has_call = false;
        let mut has_return = false;
        let mut log_count = 1; // Current LOG

        // Check for function boundaries
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x63 => has_function_entry = true, // PUSH4 (selector)
                    0x55 => has_sstore = true, // State change
                    0xf1 | 0xfa => has_call = true, // External call
                    _ => {}
                }
            }
        }

        // Count LOGs and check for return
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xa0..=0xa4 => log_count += 1, // Additional LOGs
                    0xf3 => has_return = true, // RETURN
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        // Function that only emits events
        has_function_entry && log_count >= 1 && has_return && !has_sstore && !has_call
    }

    fn has_event_spam_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut log_count = 1; // Current LOG
        let mut has_loop = false;
        let mut in_short_span = false;

        // Count LOGs in short span
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xa0..=0xa4 => {
                        log_count += 1;
                        if offset < 20 {
                            in_short_span = true;
                        }
                    }
                    0x57 => has_loop = true, // JUMPI (loop)
                    _ => {}
                }
            }
        }

        // Multiple events in short span or loop
        (log_count >= 3 && in_short_span) || (log_count >= 2 && has_loop)
    }

    fn is_log_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0-LOG4
    }
}
