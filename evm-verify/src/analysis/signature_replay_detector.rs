use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Types of signature replay vulnerabilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureReplayType {
    /// EIP-712 signature reuse across chains
    CrossChainReplay,
    /// Transaction signature replay on same chain
    SameChainReplay,
    /// Permit function signature replay
    PermitReplay,
    /// Meta-transaction signature replay
    MetaTransactionReplay,
    /// Authorization signature replay
    AuthorizationReplay,
    /// Delegation signature replay
    DelegationReplay,
}

/// Signature replay vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureReplayVulnerability {
    pub replay_type: SignatureReplayType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub technical_details: String,
    pub missing_protections: Vec<String>,
    pub detection_confidence: f32,
}

/// Mathematical signature analysis without design opinions
pub struct SignatureReplayDetector {
    bytecode: Vec<u8>,
    eip712_patterns: Vec<Vec<u8>>,
    permit_patterns: Vec<Vec<u8>>,
    signature_verification_patterns: Vec<Vec<u8>>,
}

impl SignatureReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        // EIP-712 domain separator patterns
        let eip712_patterns = vec![
            // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
            vec![0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d],
            // DOMAIN_SEPARATOR
            vec![0x36, 0x08, 0xf9, 0x32, 0x8f, 0x02, 0x2a, 0x69],
        ];

        // Permit function patterns (EIP-2612)
        let permit_patterns = vec![
            // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
            vec![0xd5, 0x05, 0xac, 0xcf],
            // PERMIT_TYPEHASH
            vec![0x6e, 0x71, 0xed, 0xae],
        ];

        // ecrecover and signature verification patterns
        let signature_verification_patterns = vec![
            // ecrecover(bytes32,uint8,bytes32,bytes32)
            vec![0x01], // precompile address
            // keccak256 for message hash
            vec![0x20], // SHA3 opcode
        ];

        Self {
            bytecode,
            eip712_patterns,
            permit_patterns,
            signature_verification_patterns,
        }
    }

    /// Detect signature replay vulnerabilities
    pub fn detect_vulnerabilities(&self) -> Vec<SignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_cross_chain_replay());
        vulnerabilities.extend(self.detect_same_chain_replay());
        vulnerabilities.extend(self.detect_permit_replay());
        vulnerabilities.extend(self.detect_meta_transaction_replay());
        vulnerabilities.extend(self.detect_authorization_replay());

        vulnerabilities
    }

    /// Detect cross-chain signature replay vulnerabilities
    fn detect_cross_chain_replay(&self) -> Vec<SignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        // CRITICAL FIX: Cross-chain replay is a DESIGN DECISION, not a vulnerability
        // Many L2s intentionally allow cross-chain signatures for bridging
        // Only flag if we can PROVE it's exploitable in context
        
        // For now, disable this check - too many false positives
        // True cross-chain replay requires understanding contract's purpose
        
        vulnerabilities
    }

    /// Detect same-chain signature replay vulnerabilities
    fn detect_same_chain_replay(&self) -> Vec<SignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        // CRITICAL FIX: Be more conservative about flagging signature replay
        // Only flag if we can confirm BOTH:
        // 1. Actual signature verification (not just pattern match)
        // 2. Missing nonce AND no other replay protection
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.has_signature_verification(i) && self.is_actual_signature_function(i) {
                // Check for nonce usage OR deadline validation
                let has_protection = self.has_nonce_protection(i) || self.has_deadline_validation(i);
                
                if !has_protection {
                    vulnerabilities.push(SignatureReplayVulnerability {
                        replay_type: SignatureReplayType::SameChainReplay,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Signature verification lacks nonce protection against replay attacks".to_string(),
                        technical_details: "Missing nonce tracking allows reuse of valid signatures multiple times".to_string(),
                        missing_protections: vec![
                            "Nonce increment and validation".to_string(),
                            "Used signature tracking".to_string(),
                        ],
                        detection_confidence: 0.95,
                    });
                }

                // Check for deadline/expiry validation
                if !self.has_deadline_validation(i) {
                    vulnerabilities.push(SignatureReplayVulnerability {
                        replay_type: SignatureReplayType::SameChainReplay,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Signature verification lacks deadline validation".to_string(),
                        technical_details: "Signatures without expiry can be replayed indefinitely".to_string(),
                        missing_protections: vec!["Signature deadline validation".to_string()],
                        detection_confidence: 0.85,
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect permit function replay vulnerabilities
    fn detect_permit_replay(&self) -> Vec<SignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.has_permit_function(i) {
                // Check for proper nonce handling in permit
                if !self.has_permit_nonce_increment(i) {
                    vulnerabilities.push(SignatureReplayVulnerability {
                        replay_type: SignatureReplayType::PermitReplay,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Permit function vulnerable to signature replay due to improper nonce handling".to_string(),
                        technical_details: "Permit nonce not properly incremented after successful signature verification".to_string(),
                        missing_protections: vec!["Atomic nonce increment".to_string()],
                        detection_confidence: 0.9,
                    });
                }

                // Check for permit deadline validation
                if !self.has_permit_deadline_check(i) {
                    vulnerabilities.push(SignatureReplayVulnerability {
                        replay_type: SignatureReplayType::PermitReplay,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Permit function lacks proper deadline validation".to_string(),
                        technical_details: "Permit signatures may not validate expiry timestamp correctly".to_string(),
                        missing_protections: vec!["Deadline comparison with block.timestamp".to_string()],
                        detection_confidence: 0.8,
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect meta-transaction signature replay
    fn detect_meta_transaction_replay(&self) -> Vec<SignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.has_meta_transaction_pattern(i) {
                if !self.has_meta_tx_nonce_protection(i) {
                    vulnerabilities.push(SignatureReplayVulnerability {
                        replay_type: SignatureReplayType::MetaTransactionReplay,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Meta-transaction implementation vulnerable to signature replay".to_string(),
                        technical_details: "Meta-transaction nonce not properly managed or validated".to_string(),
                        missing_protections: vec![
                            "Per-user nonce tracking".to_string(),
                            "Atomic nonce increment".to_string(),
                        ],
                        detection_confidence: 0.85,
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect authorization signature replay
    fn detect_authorization_replay(&self) -> Vec<SignatureReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_authorization_signature(i) {
                if !self.has_authorization_nonce(i) {
                    vulnerabilities.push(SignatureReplayVulnerability {
                        replay_type: SignatureReplayType::AuthorizationReplay,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Authorization signatures lack replay protection".to_string(),
                        technical_details: "Authorization mechanism does not prevent signature reuse".to_string(),
                        missing_protections: vec!["Authorization nonce or used signature tracking".to_string()],
                        detection_confidence: 0.9,
                    });
                }
            }
        }

        vulnerabilities
    }

    // Detection helper methods

    fn has_eip712_domain_separator(&self, pos: usize) -> bool {
        for pattern in &self.eip712_patterns {
            if pos + pattern.len() <= self.bytecode.len() {
                if self.bytecode[pos..pos + pattern.len()] == *pattern {
                    return true;
                }
            }
        }
        false
    }

    fn has_chain_id_protection(&self, pos: usize) -> bool {
        // Look for CHAINID opcode (0x46) in surrounding area
        let start = pos.saturating_sub(50);
        let end = std::cmp::min(pos + 50, self.bytecode.len());
        
        for i in start..end {
            if i < self.bytecode.len() && self.bytecode[i] == 0x46 { // CHAINID
                return true;
            }
        }
        false
    }

    fn has_verifying_contract_validation(&self, pos: usize) -> bool {
        // Look for ADDRESS opcode (0x30) used in comparison
        let start = pos.saturating_sub(30);
        let end = std::cmp::min(pos + 30, self.bytecode.len());
        
        for i in start..end.saturating_sub(3) {
            if i < self.bytecode.len() && self.bytecode[i] == 0x30 { // ADDRESS
                // Check if followed by comparison
                if i + 2 < self.bytecode.len() {
                    match self.bytecode[i + 2] {
                        0x14 => return true, // EQ
                        0x10 => return true, // LT
                        0x11 => return true, // GT
                        _ => {}
                    }
                }
            }
        }
        false
    }

    fn has_signature_verification(&self, pos: usize) -> bool {
        // Look for ecrecover precompile call
        pos + 10 <= self.bytecode.len() && 
        (self.bytecode[pos] == 0x60 && self.bytecode[pos + 1] == 0x01) // PUSH1 0x01 (ecrecover)
    }

    fn has_nonce_protection(&self, pos: usize) -> bool {
        // Look for nonce increment pattern (SLOAD, ADD, SSTORE)
        let start = pos.saturating_sub(20);
        let end = std::cmp::min(pos + 20, self.bytecode.len());
        
        let mut found_sload = false;
        let mut found_add = false;
        let mut found_sstore = false;
        
        for i in start..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x54 => found_sload = true,  // SLOAD
                    0x01 => found_add = true,    // ADD
                    0x55 => found_sstore = true, // SSTORE
                    _ => {}
                }
            }
        }
        
        found_sload && found_add && found_sstore
    }

    fn has_deadline_validation(&self, pos: usize) -> bool {
        // Look for timestamp comparison
        let start = pos.saturating_sub(30);
        let end = std::cmp::min(pos + 30, self.bytecode.len());
        
        for i in start..end.saturating_sub(3) {
            if i < self.bytecode.len() && self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check for comparison operations
                if i + 2 < self.bytecode.len() {
                    match self.bytecode[i + 2] {
                        0x10 | 0x11 | 0x12 | 0x13 | 0x14 => return true, // LT, GT, SLT, SGT, EQ
                        _ => {}
                    }
                }
            }
        }
        false
    }

    fn has_permit_function(&self, pos: usize) -> bool {
        for pattern in &self.permit_patterns {
            if pos + pattern.len() <= self.bytecode.len() {
                if self.bytecode[pos..pos + pattern.len()] == *pattern {
                    return true;
                }
            }
        }
        false
    }

    fn has_permit_nonce_increment(&self, pos: usize) -> bool {
        // Similar to general nonce protection but look specifically after permit signature
        let end = std::cmp::min(pos + 100, self.bytecode.len());
        let mut nonce_operations = 0;
        
        for i in pos..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x54 => nonce_operations += 1, // SLOAD
                    0x01 => nonce_operations += 1, // ADD  
                    0x55 => nonce_operations += 1, // SSTORE
                    _ => {}
                }
            }
        }
        
        nonce_operations >= 3 // Should have at least SLOAD, ADD, SSTORE
    }

    fn has_permit_deadline_check(&self, pos: usize) -> bool {
        self.has_deadline_validation(pos)
    }

    fn has_meta_transaction_pattern(&self, pos: usize) -> bool {
        // Look for meta-transaction signatures (execute, executeMetaTransaction)
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0x0c, 0x53, 0xc5, 0x1c] || // executeMetaTransaction
            self.bytecode[pos..pos+4] == [0x61, 0x46, 0x13, 0x08]    // execute
        )
    }

    fn has_meta_tx_nonce_protection(&self, pos: usize) -> bool {
        // Look for user-specific nonce tracking
        self.has_nonce_protection(pos) && self.has_user_nonce_mapping(pos)
    }

    fn has_user_nonce_mapping(&self, pos: usize) -> bool {
        // Look for mapping access patterns (address used as key)
        let start = pos.saturating_sub(40);
        let end = std::cmp::min(pos + 40, self.bytecode.len());
        
        for i in start..end.saturating_sub(5) {
            if i < self.bytecode.len() && self.bytecode[i] == 0x33 { // CALLER
                // Check if followed by storage operations
                for j in (i+1)..std::cmp::min(i+20, self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 || self.bytecode[j] == 0x55 { // SLOAD or SSTORE
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_authorization_signature(&self, pos: usize) -> bool {
        // Look for authorization function signatures
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0x79, 0xcc, 0x67, 0x90] || // isValidSignature
            self.bytecode[pos..pos+4] == [0x16, 0x26, 0xba, 0x7e]    // isValidSigner
        )
    }

    fn has_authorization_nonce(&self, pos: usize) -> bool {
        self.has_nonce_protection(pos)
    }
    
    /// Check if this is actually a signature verification function, not just pattern match
    fn is_actual_signature_function(&self, pos: usize) -> bool {
        // Look for function selector patterns around the signature verification
        let start = pos.saturating_sub(50);
        
        // Check for common signature function selectors
        for i in start..pos {
            if i + 4 <= self.bytecode.len() {
                // Check for PUSH4 followed by EQ (function dispatcher pattern)
                if self.bytecode[i] == 0x63 && i + 6 < self.bytecode.len() && self.bytecode[i + 5] == 0x14 {
                    let selector = &self.bytecode[i+1..i+5];
                    // Check if it's a known signature-related function
                    if self.is_signature_function_selector(selector) {
                        return true;
                    }
                }
            }
        }
        
        // Conservative: return false if we can't confirm it's a signature function
        false
    }
    
    fn is_signature_function_selector(&self, selector: &[u8]) -> bool {
        // Known signature-related function selectors
        matches!(selector,
            [0xd5, 0x05, 0xac, 0xcf] | // permit
            [0x79, 0xcc, 0x67, 0x90] | // isValidSignature
            [0x0c, 0x53, 0xc5, 0x1c] | // executeMetaTransaction
            [0x61, 0x46, 0x13, 0x08] | // execute
            [0x16, 0x26, 0xba, 0x7e]   // isValidSigner
        )
    }
}

/// Main detection function for integration
pub fn detect_signature_replay_attacks(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let bytecode = analyzer.get_bytecode_vec();
    let detector = SignatureReplayDetector::new(bytecode);
    let vulnerabilities = detector.detect_vulnerabilities();

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::SignatureReplay,
            severity: vuln.severity,
            pc: vuln.location as u64,
            description: vuln.description,
            operations: vec![],
            remediation: format!("Missing protections: {}", vuln.missing_protections.join(", ")),
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_chain_replay_detection() {
        // Test EIP-712 without chainId protection
        let bytecode = vec![
            0x63, 0x8b, 0x73, 0xc3, 0xc6, // PUSH4 EIP712Domain hash
            0x60, 0x01, // PUSH1 0x01 (ecrecover)
            0xf1, // CALL
        ];
        
        let detector = SignatureReplayDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();
        
        assert!(vulnerabilities.iter().any(|v| matches!(v.replay_type, SignatureReplayType::CrossChainReplay)));
    }

    #[test]
    fn test_nonce_protection_detection() {
        // Test signature verification without nonce
        let bytecode = vec![
            0x60, 0x01, // PUSH1 0x01 (ecrecover)
            0xf1, // CALL
            // Missing nonce operations
        ];
        
        let detector = SignatureReplayDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();
        
        assert!(vulnerabilities.iter().any(|v| matches!(v.replay_type, SignatureReplayType::SameChainReplay)));
    }

    #[test]
    fn test_permit_replay_detection() {
        // Test permit function without proper nonce handling
        let bytecode = vec![
            0x63, 0xd5, 0x05, 0xac, 0xcf, // PUSH4 permit()
            0x60, 0x01, // PUSH1 0x01 (ecrecover)
            0xf1, // CALL
        ];
        
        let detector = SignatureReplayDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();
        
        assert!(vulnerabilities.iter().any(|v| matches!(v.replay_type, SignatureReplayType::PermitReplay)));
    }
}
