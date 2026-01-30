use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Missing Indexed Event Field Detector
///
/// Detects events that should have indexed parameters for efficient filtering
/// but are missing the indexed keyword, making them inefficient to query.
///
/// Impact: Poor off-chain query performance, increased RPC costs
/// Best Practice: Key fields like addresses, token IDs, and amounts should be indexed
///
/// Detection Strategy:
/// - Identifies LOG operations (LOG0-LOG4)
/// - Analyzes event signatures and parameter patterns
/// - Detects events with address/uint256 parameters that aren't indexed
/// - Checks for transfer-like events without indexed sender/receiver
pub struct MissingIndexedEventFieldDetector;

impl MissingIndexedEventFieldDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: LOG1 with address parameter (should be indexed)
            // LOG1 (0xa1) with only one topic but address data
            if bytecode[i] == 0xa1 {
                if self.has_unindexed_address_parameter(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Low,
                        description: "Event with address parameter not indexed: Inefficient for filtering, should use indexed keyword".to_string(),
                        pc: i,
                        confidence: 0.81,
                    });
                }
            }

            // Pattern 2: LOG1 with uint256 ID (should be indexed for NFT/token events)
            if bytecode[i] == 0xa1 {
                if self.has_unindexed_id_parameter(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Low,
                        description: "Event with ID/amount parameter not indexed: Consider indexing for efficient queries".to_string(),
                        pc: i,
                        confidence: 0.78,
                    });
                }
            }

            // Pattern 3: Transfer-like event without indexed sender/receiver
            // LOG1 with Transfer signature but only one indexed parameter
            if bytecode[i] == 0xa1 || bytecode[i] == 0xa2 {
                if self.has_transfer_event_missing_indexed(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Transfer-like event missing indexed parameters: Sender and receiver should be indexed".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 4: LOG0 (anonymous event) with important data
            if bytecode[i] == 0xa0 {
                if self.has_anonymous_event_with_important_data(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Anonymous event with important data: Consider making non-anonymous with indexed parameters".to_string(),
                        pc: i,
                        confidence: 0.76,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_unindexed_address_parameter(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_address_load = false;
        let mut data_size = 0;

        // Check for address loading (20 bytes)
        for offset in 1..=lookback {
            if pos >= offset && bytecode[pos - offset] == 0x73 {
                // PUSH20 (address)
                has_address_load = true;
            }
            if pos >= offset && bytecode[pos - offset] == 0x60 {
                // PUSH1 with potential data size
                if pos >= offset + 1 && bytecode[pos - offset + 1] == 0x20 {
                    data_size = 32; // 32 bytes data
                }
            }
        }

        // LOG1 with address data but not in topic (should be LOG2 or LOG3)
        has_address_load && data_size > 0
    }

    fn has_unindexed_id_parameter(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut has_id_pattern = false;
        let mut mload_count = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x51 => mload_count += 1, // MLOAD (loading ID)
                    0x60..=0x7f => {
                        // PUSH operations with potential ID
                        has_id_pattern = true;
                    }
                    _ => {}
                }
            }
        }

        // Pattern suggests ID/tokenId but only 1 topic (event signature only)
        has_id_pattern && mload_count >= 1
    }

    fn has_transfer_event_missing_indexed(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut address_loads = 0;
        let mut has_amount = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x73 => address_loads += 1, // PUSH20 (address)
                    0x51 => has_amount = true, // MLOAD (amount)
                    _ => {}
                }
            }
        }

        // Transfer pattern: 2 addresses + amount but only LOG1 or LOG2
        // Should be LOG3 or LOG4 with indexed from/to
        let is_log1 = bytecode[pos] == 0xa1;
        let is_log2 = bytecode[pos] == 0xa2;
        
        (is_log1 || is_log2) && address_loads >= 2 && has_amount
    }

    fn has_anonymous_event_with_important_data(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_address = false;
        let mut has_value = false;
        let mut mstore_count = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x73 => has_address = true, // PUSH20
                    0x51 => has_value = true, // MLOAD
                    0x52 => mstore_count += 1, // MSTORE (preparing data)
                    _ => {}
                }
            }
        }

        // Anonymous event (LOG0) with substantial data that should be indexed
        has_address && has_value && mstore_count >= 2
    }
}
