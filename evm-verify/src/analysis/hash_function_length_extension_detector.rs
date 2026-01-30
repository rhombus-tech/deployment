// Hash Function Length Extension Detector
// Detects Merkle tree manipulation and hash length extension vulnerabilities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashFunctionLengthExtensionVulnerability {
    pub location: usize,
    pub vulnerability_type: HashExtensionType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashExtensionType {
    MerkleTreeManipulation,          // Merkle tree structure vulnerable
    LengthExtensionAttack,           // Hash construction allows extension
    SecondPreimageVulnerability,     // Second preimage attack possible
    CollisionResistanceWeak,         // Weak collision resistance
    MessagePaddingExploit,           // Padding oracle or manipulation
    HashConcatenationUnsafe,         // Unsafe hash concatenation
}

pub struct HashFunctionLengthExtensionDetector {
    bytecode: Vec<u8>,
}

impl HashFunctionLengthExtensionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HashFunctionLengthExtensionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_merkle_tree_manipulation() {
            vulnerabilities.push(HashFunctionLengthExtensionVulnerability {
                location: loc,
                vulnerability_type: HashExtensionType::MerkleTreeManipulation,
                severity: SecuritySeverity::Critical,
                description: "Merkle tree verification vulnerable to manipulation. Proof verification \
                             logic allows forged proofs or intermediate node injection.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_length_extension_attack() {
            vulnerabilities.push(HashFunctionLengthExtensionVulnerability {
                location: loc,
                vulnerability_type: HashExtensionType::LengthExtensionAttack,
                severity: SecuritySeverity::High,
                description: "Hash construction vulnerable to length extension. Attacker can append \
                             data to hash input and forge valid hashes without knowing secret.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_second_preimage_vulnerability() {
            vulnerabilities.push(HashFunctionLengthExtensionVulnerability {
                location: loc,
                vulnerability_type: HashExtensionType::SecondPreimageVulnerability,
                severity: SecuritySeverity::Critical,
                description: "Second preimage attack possible. Weak hash construction allows finding \
                             alternative inputs producing same hash enabling forgery.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_collision_resistance_weak() {
            vulnerabilities.push(HashFunctionLengthExtensionVulnerability {
                location: loc,
                vulnerability_type: HashExtensionType::CollisionResistanceWeak,
                severity: SecuritySeverity::High,
                description: "Hash collision resistance inadequate. Short hash output or weak \
                             algorithm allows collision attacks on critical operations.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_message_padding_exploit() {
            vulnerabilities.push(HashFunctionLengthExtensionVulnerability {
                location: loc,
                vulnerability_type: HashExtensionType::MessagePaddingExploit,
                severity: SecuritySeverity::Medium,
                description: "Message padding manipulable. Padding oracle or malformed padding \
                             allows hash manipulation or information leakage.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_hash_concatenation_unsafe() {
            vulnerabilities.push(HashFunctionLengthExtensionVulnerability {
                location: loc,
                vulnerability_type: HashExtensionType::HashConcatenationUnsafe,
                severity: SecuritySeverity::High,
                description: "Hash concatenation without proper separation. Combined hashes lack \
                             domain separation enabling cross-context collision attacks.".to_string(),
                confidence: 0.88,
            });
        }

        vulnerabilities
    }

    fn detect_merkle_tree_manipulation(&self) -> Option<usize> {
        // Pattern: Merkle proof verification without proper checks
        // Sequential hashing without validating tree structure
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x20 {  // SHA3 (hash operation)
                let mut is_merkle_verification = false;
                let mut has_depth_check = false;
                
                // Check if part of iterative hashing (Merkle proof)
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Loop back for multiple hashes
                    if self.bytecode[j] == 0x56 {  // JUMP (loop)
                        is_merkle_verification = true;
                    }
                }
                
                // Check for depth/path length validation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (depth counter)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (max depth check)
                                has_depth_check = true;
                            }
                        }
                    }
                }
                
                if is_merkle_verification && !has_depth_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_length_extension_attack(&self) -> Option<usize> {
        // Pattern: Hash used as MAC without HMAC construction
        // SHA3 of secret || message without proper construction
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3
                let mut has_secret = false;
                let mut uses_hmac = false;
                
                // Check if hashing with secret (SLOAD before hash)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (secret)
                        has_secret = true;
                    }
                }
                
                // Check for HMAC construction (double hash with key)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {  // Second SHA3 (HMAC pattern)
                        uses_hmac = true;
                    }
                }
                
                if has_secret && !uses_hmac {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_second_preimage_vulnerability(&self) -> Option<usize> {
        // Pattern: Hash comparison without length check
        // Accepts any input producing target hash without validating length
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3 (hash input)
                let mut compared_to_target = false;
                let mut validates_length = false;
                
                // Check if hash compared to target
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (compare hash)
                        compared_to_target = true;
                    }
                }
                
                // Check for input length validation
                for j in (i.saturating_sub(20))..i {
                    // Length check before hashing
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (input)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x14 {  // LT/EQ (length)
                                validates_length = true;
                            }
                        }
                    }
                }
                
                if compared_to_target && !validates_length {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_collision_resistance_weak(&self) -> Option<usize> {
        // Pattern: Truncated hash used for critical operation
        // Hash output truncated reducing collision resistance
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3
                let mut is_truncated = false;
                let mut used_critically = false;
                
                // Check for truncation (AND with mask or byte extraction)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x16 {  // AND (mask - truncation)
                        is_truncated = true;
                    }
                    if self.bytecode[j] == 0x1A {  // BYTE (extract byte - truncation)
                        is_truncated = true;
                    }
                }
                
                // Check if used for critical operation (authorization, transfer)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (authorization check)
                        used_critically = true;
                    }
                    if self.bytecode[j] == 0xF1 {  // CALL (value transfer)
                        used_critically = true;
                    }
                }
                
                if is_truncated && used_critically {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_message_padding_exploit(&self) -> Option<usize> {
        // Pattern: Variable length input to hash without proper padding
        // User-controlled padding in hash input
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3
                let mut has_variable_input = false;
                let mut validates_padding = false;
                
                // Check for variable length input
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (user input)
                        has_variable_input = true;
                    }
                }
                
                // Check for padding validation (length multiple of block size)
                for j in (i.saturating_sub(25))..i {
                    // Padding check: length % blocksize == 0
                    if self.bytecode[j] == 0x06 {  // MOD (check padding)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (valid padding)
                                validates_padding = true;
                            }
                        }
                    }
                }
                
                if has_variable_input && !validates_padding {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_hash_concatenation_unsafe(&self) -> Option<usize> {
        // Pattern: Multiple hashes concatenated without domain separation
        // Hash1 || Hash2 used without separator or length encoding
        
        let mut hash_operations = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x20 {  // SHA3
                hash_operations.push(i);
            }
        }
        
        // Check if multiple hashes are concatenated
        if hash_operations.len() >= 2 {
            for window in hash_operations.windows(2) {
                let first = window[0];
                let second = window[1];
                
                let mut concatenates = false;
                let mut has_separator = false;
                
                // Check if hashes are combined
                for i in first..second.min(first + 30) {
                    // Concatenation or combination
                    if self.bytecode[i] == 0x20 {  // Another SHA3 (combined)
                        concatenates = true;
                    }
                }
                
                // Check for domain separator (constant mixed in)
                for i in first..second.min(first + 25) {
                    if self.bytecode[i] == 0x60 || self.bytecode[i] == 0x61 {  // PUSH (separator)
                        for j in i+1..(i+10).min(self.bytecode.len()) {
                            if self.bytecode[j] == 0x20 {  // SHA3 with separator
                                has_separator = true;
                            }
                        }
                    }
                }
                
                if concatenates && !has_separator {
                    return Some(first);
                }
            }
        }
        
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("HashFunctionLengthExtension{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Hash Function Length Extension {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Use HMAC for message authentication, validate Merkle proof depths, check \
                             input lengths before hashing, avoid hash truncation for security, validate \
                             message padding, and use domain separation in hash concatenation".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_manipulation() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x20, // SHA3 (hash)
            0x60, 0x00, // PUSH1 0
            0x56, // JUMP (loop - no depth check)
        ];
        
        let detector = HashFunctionLengthExtensionDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, HashExtensionType::MerkleTreeManipulation)));
    }

    #[test]
    fn test_length_extension_attack() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (secret)
            0x60, 0x00, // PUSH1 0
            0x20, // SHA3 (hash secret || message - no HMAC)
        ];
        
        let detector = HashFunctionLengthExtensionDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, HashExtensionType::LengthExtensionAttack)));
    }
}
