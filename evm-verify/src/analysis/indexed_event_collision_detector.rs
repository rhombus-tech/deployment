use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Indexed Event Collision Detector
///
/// Detects vulnerabilities where indexed event parameters can collide, leading to
/// incorrect event filtering, data loss, or security issues in off-chain systems.
///
/// Collision Scenarios:
/// - Same event signature with different semantics
/// - Indexed parameter hash collisions
/// - Topic collision between different events
/// - Overloaded events with ambiguous indexed params
/// - Anonymous events causing namespace pollution
///
/// Real-World Impact:
/// - Off-chain systems filtering wrong events
/// - Event collision causing data corruption
/// - Security monitors missing critical events
/// - Analytics platforms aggregating wrong data
///
/// Detection Strategy:
/// - Identifies events with overlapping topics
/// - Detects hash collision risks in indexed params
/// - Looks for anonymous events without proper namespacing
/// - Checks for event signature collisions
/// - Identifies ambiguous event parameter patterns
pub struct IndexedEventCollisionDetector;

impl IndexedEventCollisionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Anonymous event (LOG0) - high collision risk
            if bytecode[i] == 0xa0 {
                if self.has_anonymous_event_collision_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Anonymous event collision: LOG0 event without signature topic has high collision risk".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 2: Multiple events with similar topics
            if self.is_log_opcode(bytecode[i]) {
                if self.has_similar_event_topics(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Event topic collision: Multiple events with similar topics may cause filtering conflicts".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 3: Dynamic indexed parameter (hash collision)
            if self.is_log_opcode(bytecode[i]) {
                if self.has_dynamic_indexed_collision_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Dynamic indexed parameter: Hashed indexed params (string/bytes/array) vulnerable to collisions".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 4: Overloaded event pattern
            if self.is_log_opcode(bytecode[i]) {
                if self.has_overloaded_event_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Overloaded event: Multiple events with same name but different parameters cause ambiguity".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            // Pattern 5: Event without proper topic separation
            if self.is_log_opcode(bytecode[i]) {
                if self.has_insufficient_topic_separation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Low,
                        description: "Insufficient topic separation: Event uses few indexed parameters, reducing filterability".to_string(),
                        pc: i,
                        confidence: 0.81,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_anonymous_event_collision_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_multiple_data_fields = false;
        let mut mstore_count = 0;

        // Check for complex data in anonymous event
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x52 {
                    mstore_count += 1; // MSTORE (event data field)
                }
            }
        }

        if mstore_count >= 3 {
            has_multiple_data_fields = true;
        }

        // Anonymous event with multiple fields increases collision risk
        has_multiple_data_fields
    }

    fn has_similar_event_topics(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let window = 60.min(bytecode.len().saturating_sub(pos));
        
        let mut topic_hashes = Vec::new();
        let mut current_topic = None;

        // Collect topic hash (first PUSH32 before LOG)
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x7f && pos >= offset + 32 {
                    let hash = &bytecode[pos - offset + 1..pos - offset + 33];
                    current_topic = Some(hash[0..4].to_vec());
                    break;
                }
            }
        }

        if let Some(topic) = current_topic {
            topic_hashes.push(topic.clone());

            // Look for other events nearby with similar topics
            for offset in 1..window {
                if pos + offset < bytecode.len() {
                    if self.is_log_opcode(bytecode[pos + offset]) {
                        // Find topic for this event
                        for back in 1..=20 {
                            if pos + offset >= back {
                                if bytecode[pos + offset - back] == 0x7f && pos + offset >= back + 32 {
                                    let hash = &bytecode[pos + offset - back + 1..pos + offset - back + 33];
                                    let other_topic = hash[0..4].to_vec();
                                    
                                    // Check for collision in first 4 bytes
                                    if other_topic[0] == topic[0] && other_topic != topic {
                                        return true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn has_dynamic_indexed_collision_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut has_keccak = false;
        let mut has_dynamic_data = false;
        let mut has_indexed_param = false;

        // Check for KECCAK256 before LOG (hashing dynamic indexed param)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x20 => has_keccak = true, // KECCAK256
                    0x37 => has_dynamic_data = true, // CALLDATACOPY (dynamic data)
                    0x51 => {
                        // MLOAD with KECCAK suggests indexed param
                        if has_keccak {
                            has_indexed_param = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Dynamic data hashed for indexed parameter
        has_keccak && has_dynamic_data && has_indexed_param
    }

    fn has_overloaded_event_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let window = 80.min(bytecode.len().saturating_sub(pos));
        
        let mut current_param_count = 0;
        let mut has_similar_event_nearby = false;

        // Count parameters for current event
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x52 {
                    current_param_count += 1; // MSTORE (param)
                }
            }
        }

        // Look for another event with different param count but similar context
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if self.is_log_opcode(bytecode[pos + offset]) {
                    let mut other_param_count = 0;
                    
                    // Count params for other event
                    for back in 1..=30 {
                        if pos + offset >= back {
                            if bytecode[pos + offset - back] == 0x52 {
                                other_param_count += 1;
                            }
                        }
                    }

                    // Different param counts suggest overloading
                    if other_param_count != current_param_count && other_param_count > 0 {
                        has_similar_event_nearby = true;
                        break;
                    }
                }
            }
        }

        current_param_count >= 2 && has_similar_event_nearby
    }

    fn has_insufficient_topic_separation(&self, bytecode: &[u8], pos: usize) -> bool {
        let log_opcode = bytecode[pos];
        
        // LOG0 = no topics (anonymous)
        // LOG1 = 1 topic (event signature only)
        // LOG2 = 1 indexed param
        // LOG3 = 2 indexed params
        // LOG4 = 3 indexed params
        
        match log_opcode {
            0xa0 => true,  // LOG0 - no signature topic
            0xa1 => true,  // LOG1 - signature only, no indexed params
            0xa2 => {      // LOG2 - only 1 indexed param
                let lookback = 25.min(pos);
                let mut param_count = 0;
                
                // Count total parameters
                for offset in 1..=lookback {
                    if pos >= offset && bytecode[pos - offset] == 0x52 {
                        param_count += 1;
                    }
                }
                
                // Many params but only 1 indexed
                param_count >= 4
            }
            _ => false,
        }
    }

    fn is_log_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0-LOG4
    }
}
