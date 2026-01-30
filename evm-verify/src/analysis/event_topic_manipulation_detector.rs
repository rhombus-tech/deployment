use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Event Topic Manipulation Detector
///
/// Detects vulnerabilities where event topics can be manipulated to emit misleading
/// events, bypass filters, or exploit off-chain systems relying on event data.
///
/// Manipulation Vectors:
/// - User-controlled data in indexed parameters
/// - Topic values constructed from untrusted input
/// - Event signatures modified dynamically
/// - Malicious topic values matching legitimate events
/// - Topic spoofing to bypass security monitors
///
/// Real-World Impact:
/// - Security monitors bypassed via crafted topics
/// - Off-chain systems processing fake events
/// - Event filters returning wrong data
/// - Analytics platforms corrupted by topic manipulation
///
/// Detection Strategy:
/// - Identifies user input used directly in topics
/// - Detects dynamic topic construction
/// - Looks for topic values from calldata
/// - Checks for unchecked topic parameters
/// - Identifies topic manipulation patterns
pub struct EventTopicManipulationDetector;

impl EventTopicManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Topic from calldata (user-controlled)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_topic_from_calldata(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "User-controlled event topic: Topic value from calldata enables event spoofing and filter bypass".to_string(),
                        pc: i,
                        confidence: 0.90,
                    });
                }
            }

            // Pattern 2: Dynamic topic construction
            if self.is_log_opcode(bytecode[i]) {
                if self.has_dynamic_topic_construction(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Dynamic topic construction: Topics built from variables can be manipulated to bypass event filters".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: Topic from storage without validation
            if self.is_log_opcode(bytecode[i]) {
                if self.has_unvalidated_storage_topic(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unvalidated storage topic: Topic from storage without validation can be manipulated".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 4: Computed topic signature
            if self.is_log_opcode(bytecode[i]) {
                if self.has_computed_event_signature(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Computed event signature: Event signature computed at runtime may enable topic manipulation".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 5: Topic from external call return
            if self.is_log_opcode(bytecode[i]) {
                if self.has_topic_from_external_source(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "External source topic: Topic value from external call can be manipulated by attacker".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_topic_from_calldata(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut has_calldataload = false;
        let mut used_as_topic = false;

        // Check if calldata is loaded and used as topic
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_calldataload = true, // CALLDATALOAD
                    0x51 => {
                        // MLOAD - might be loading topic from memory
                        if has_calldataload {
                            used_as_topic = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calldata used directly as topic (not just event data)
        has_calldataload && (used_as_topic || self.has_minimal_operations_between(bytecode, pos, lookback))
    }

    fn has_dynamic_topic_construction(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_arithmetic = false;
        let mut has_sload = false;
        let mut has_topic_ops = 0;

        // Check for topic construction via operations
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x01 | 0x02 | 0x03 => has_arithmetic = true, // ADD, MUL, SUB
                    0x16 | 0x17 | 0x18 | 0x19 => has_arithmetic = true, // AND, OR, XOR, NOT
                    0x54 => has_sload = true, // SLOAD
                    0x51 | 0x52 => has_topic_ops += 1, // MLOAD, MSTORE (topic prep)
                    _ => {}
                }
            }
        }

        // Topic constructed from operations
        has_arithmetic && has_sload && has_topic_ops >= 2
    }

    fn has_unvalidated_storage_topic(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_sload = false;
        let mut has_validation = false;
        let mut direct_to_topic = false;

        // Check if storage value used as topic
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => has_sload = true, // SLOAD
                    0x14 | 0x10 | 0x11 => has_validation = true, // EQ, LT, GT (validation)
                    0x15 => has_validation = true, // ISZERO (check)
                    0x51 => {
                        // MLOAD after SLOAD with few ops between
                        if has_sload && !has_validation {
                            direct_to_topic = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Storage value as topic without validation
        has_sload && !has_validation && direct_to_topic
    }

    fn has_computed_event_signature(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut has_keccak = false;
        let mut has_string_ops = false;
        let mut builds_signature = false;

        // Check for event signature computation
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x20 => has_keccak = true, // KECCAK256 (computing signature)
                    0x52 => has_string_ops = true, // MSTORE (building string)
                    0x37 => has_string_ops = true, // CALLDATACOPY
                    _ => {}
                }
            }
        }

        if has_keccak && has_string_ops {
            builds_signature = true;
        }

        // Event signature computed at runtime
        builds_signature
    }

    fn has_topic_from_external_source(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_external_call = false;
        let mut has_returndatacopy = false;
        let mut used_as_topic = false;

        // Check for external call return data as topic
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xf1 | 0xfa | 0xf4 => has_external_call = true, // CALL, STATICCALL, DELEGATECALL
                    0x3e => has_returndatacopy = true, // RETURNDATACOPY
                    0x51 => {
                        // MLOAD after return data copy
                        if has_returndatacopy {
                            used_as_topic = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // External call return used as topic
        has_external_call && has_returndatacopy && used_as_topic
    }

    fn has_minimal_operations_between(&self, bytecode: &[u8], pos: usize, lookback: usize) -> bool {
        let mut operation_count = 0;
        
        for offset in 1..=lookback {
            if pos >= offset {
                let opcode = bytecode[pos - offset];
                // Count significant operations (not just stack manipulation)
                if matches!(opcode, 0x01..=0x1f | 0x20 | 0x30..=0x48 | 0x50..=0x5b) {
                    operation_count += 1;
                }
            }
        }

        // Few operations between calldata load and log
        operation_count <= 3
    }

    fn is_log_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0-LOG4
    }
}
