use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Event Emission Front-running Detector
///
/// Detects vulnerabilities where event emissions can be front-run or manipulated
/// to gain unfair advantages in time-sensitive operations or off-chain systems.
///
/// Attack Vectors:
/// - Front-running event-triggered actions (auctions, trades)
/// - MEV extraction based on event observation
/// - Oracle updates front-run via event monitoring
/// - Off-chain systems exploited via event manipulation
/// - Transaction ordering based on event detection
///
/// Real-World Cases:
/// - NFT auctions front-run via event monitoring
/// - DEX trades front-run after Swap events
/// - Liquidation events front-run for MEV
/// - Governance votes front-run via ProposalCreated events
///
/// Detection Strategy:
/// - Identifies critical events without access control
/// - Detects state changes visible via events before completion
/// - Looks for events in public functions without ordering protection
/// - Checks for time-sensitive operations emitting events
/// - Identifies MEV-vulnerable event patterns
pub struct EventEmissionFrontrunningDetector;

impl EventEmissionFrontrunningDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: LOG before state commitment (front-runnable)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_log_before_state_change(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Event emission front-running: Event logged before state commitment enables front-running attacks".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: Price update event (MEV vulnerable)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_price_update_event_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Price update event: Price change events enable sandwich attacks and MEV extraction".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: Auction/bid event without commit-reveal
            if self.is_log_opcode(bytecode[i]) {
                if self.has_auction_event_without_protection(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Auction event front-running: Bid/auction events without commit-reveal scheme enable front-running".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 4: Event in public function without ordering protection
            if self.is_log_opcode(bytecode[i]) {
                if self.has_unprotected_public_event(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Unprotected event emission: Public function emits events without transaction ordering protection".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 5: Multiple events in sequence (information leakage)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_sequential_event_leakage(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Sequential event leakage: Multiple events reveal transaction intent before completion".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_log_before_state_change(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sstore_after = false;
        let mut has_call_after = false;

        // Check if critical state changes happen AFTER event
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x55 => has_sstore_after = true, // SSTORE after event
                    0xf1 | 0xfa => has_call_after = true, // External call after event
                    _ => {}
                }
            }
        }

        // Event before state finalization
        has_sstore_after || has_call_after
    }

    fn has_price_update_event_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut has_price_calc = false;
        let mut has_div_or_mul = false;
        let mut has_sload = false;

        // Check for price calculation before event
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x02 | 0x04 => has_div_or_mul = true, // MUL, DIV (price calc)
                    0x54 => has_sload = true, // SLOAD (reading reserves/balance)
                    0x47 => has_price_calc = true, // SELFBALANCE (price calculation)
                    _ => {}
                }
            }
        }

        // Price calculation followed by event emission
        has_price_calc && has_div_or_mul && has_sload
    }

    fn has_auction_event_without_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_value_comparison = false;
        let mut has_timestamp_check = false;
        let mut has_commit_hash = false;

        // Check for auction/bid pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x34 => has_value_comparison = true, // CALLVALUE (bid amount)
                    0x10 | 0x11 => has_value_comparison = true, // LT, GT (bid comparison)
                    0x42 => has_timestamp_check = true, // TIMESTAMP (auction timing)
                    0x20 => has_commit_hash = true, // KECCAK256 (commit-reveal)
                    _ => {}
                }
            }
        }

        // Auction event without commit-reveal protection
        has_value_comparison && has_timestamp_check && !has_commit_hash
    }

    fn has_unprotected_public_event(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut is_public_function = false;
        let mut has_access_control = false;
        let mut has_ordering_protection = false;

        // Check function context
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x63 => is_public_function = true, // PUSH4 (function selector)
                    0x33 => has_access_control = true, // CALLER (access check)
                    0x42 => has_ordering_protection = true, // TIMESTAMP (ordering)
                    0x43 => has_ordering_protection = true, // NUMBER (block ordering)
                    _ => {}
                }
            }
        }

        // Public function event without protection
        is_public_function && !has_access_control && !has_ordering_protection
    }

    fn has_sequential_event_leakage(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let lookback = 15.min(pos);
        let mut event_count = 1; // Current LOG
        let mut has_state_change = false;

        // Count events before
        for offset in 1..=lookback {
            if pos >= offset {
                if self.is_log_opcode(bytecode[pos - offset]) {
                    event_count += 1;
                }
            }
        }

        // Count events after and check for state changes
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if self.is_log_opcode(bytecode[pos + offset]) {
                    event_count += 1;
                }
                if bytecode[pos + offset] == 0x55 {
                    has_state_change = true;
                }
            }
        }

        // Multiple events revealing intent
        event_count >= 3 && has_state_change
    }

    fn is_log_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0-LOG4
    }
}
