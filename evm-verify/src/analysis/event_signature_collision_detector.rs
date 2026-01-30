use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Event Signature Collision Detector
///
/// Detects potential event signature collisions where different events
/// could produce the same topic0 hash, causing confusion in event parsing.
///
/// Impact: Event parsing errors, incorrect off-chain indexing, security issues
/// Risk: Critical when events control access or financial logic
///
/// Detection Strategy:
/// - Identifies multiple LOG operations with similar signatures
/// - Detects events with same parameter types but different names
/// - Checks for hash collisions in event signatures
/// - Looks for ambiguous event definitions that could collide
pub struct EventSignatureCollisionDetector;

impl EventSignatureCollisionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;
        let mut event_signatures = Vec::new();

        // First pass: collect event signatures
        while i < bytecode.len() {
            if self.is_log_operation(bytecode[i]) {
                if let Some(sig_hash) = self.extract_event_signature_hash(bytecode, i) {
                    event_signatures.push((i, sig_hash));
                }
            }
            i += 1;
        }

        // Second pass: detect collisions
        for idx in 0..event_signatures.len() {
            for jdx in (idx + 1)..event_signatures.len() {
                if self.has_potential_collision(&event_signatures[idx].1, &event_signatures[jdx].1) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: format!(
                            "Potential event signature collision detected: Events at {} and {} may have colliding signatures",
                            event_signatures[idx].0, event_signatures[jdx].0
                        ),
                        pc: event_signatures[idx].0,
                        confidence: 0.79,
                    });
                }
            }
        }

        // Check for ambiguous event patterns
        let mut i = 0;
        while i < bytecode.len() {
            if self.is_log_operation(bytecode[i]) {
                if self.has_ambiguous_event_signature(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Event with ambiguous signature: Similar parameter types may cause parsing confusion".to_string(),
                        pc: i,
                        confidence: 0.75,
                    });
                }

                // Check for overloaded events (same name, different params)
                if self.has_overloaded_event_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Overloaded event detected: Multiple events with similar signatures increase collision risk".to_string(),
                        pc: i,
                        confidence: 0.82,
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

    fn extract_event_signature_hash(&self, bytecode: &[u8], pos: usize) -> Option<[u8; 4]> {
        let lookback = 35.min(pos);
        
        // Look for PUSH32 with event signature hash
        for offset in 1..=lookback {
            if pos >= offset && bytecode[pos - offset] == 0x7f {
                // PUSH32 - likely contains event signature hash
                if pos >= offset + 4 {
                    let hash_start = pos - offset + 1;
                    if hash_start + 4 <= bytecode.len() {
                        let mut hash = [0u8; 4];
                        hash.copy_from_slice(&bytecode[hash_start..hash_start + 4]);
                        return Some(hash);
                    }
                }
            }
        }
        None
    }

    fn has_potential_collision(&self, sig1: &[u8; 4], sig2: &[u8; 4]) -> bool {
        // Check if first 3 bytes match (high collision probability)
        sig1[0] == sig2[0] && sig1[1] == sig2[1] && sig1[2] == sig2[2]
    }

    fn has_ambiguous_event_signature(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut uint256_count = 0;
        let mut address_count = 0;
        let mut generic_params = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x60 => {
                        // PUSH1 - check for uint256 size (32 bytes)
                        if pos >= offset + 1 && bytecode[pos - offset + 1] == 0x20 {
                            uint256_count += 1;
                        }
                    }
                    0x73 => address_count += 1, // PUSH20 (address)
                    0x51 | 0x52 => generic_params += 1, // MLOAD/MSTORE
                    _ => {}
                }
            }
        }

        // Ambiguous if multiple uint256 or generic parameters without clear distinction
        (uint256_count >= 3 && address_count == 0) || (generic_params >= 4)
    }

    fn has_overloaded_event_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 45.min(pos);
        let window = 45.min(bytecode.len().saturating_sub(pos));
        let mut signature_hashes = Vec::new();

        // Look backward for similar event patterns
        for offset in 1..=lookback {
            if pos >= offset && self.is_log_operation(bytecode[pos - offset]) {
                if let Some(hash) = self.extract_event_signature_hash(bytecode, pos - offset) {
                    signature_hashes.push(hash);
                }
            }
        }

        // Look forward for similar event patterns
        for offset in 0..window {
            if pos + offset < bytecode.len() && self.is_log_operation(bytecode[pos + offset]) {
                if let Some(hash) = self.extract_event_signature_hash(bytecode, pos + offset) {
                    signature_hashes.push(hash);
                }
            }
        }

        // Check if we have multiple similar signatures nearby
        for i in 0..signature_hashes.len() {
            for j in (i + 1)..signature_hashes.len() {
                if self.has_potential_collision(&signature_hashes[i], &signature_hashes[j]) {
                    return true;
                }
            }
        }

        false
    }
}
