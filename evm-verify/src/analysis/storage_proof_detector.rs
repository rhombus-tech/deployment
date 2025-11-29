/// Storage Proof Verification Bypass Detector
/// Detects vulnerabilities in Merkle proof and storage proof verification
/// Critical for: Cross-chain bridges, L2 withdrawals, state proofs

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofVulnerability {
    pub vulnerability_type: StorageProofIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageProofIssueType {
    UncheckedProofVerification,    // Proof not validated
    StorageRootNotVerified,        // Storage root not checked against block hash
    ProofReplayAttack,             // Proof can be reused
    InvalidWitnessAccepted,        // Invalid witness data accepted
    MerkleProofBypass,             // Merkle proof check can be skipped
    IncorrectProofLength,          // Proof length not validated
    MissingNonceCheck,             // Transaction nonce not verified
}

pub struct StorageProofDetector {
    bytecode: Vec<u8>,
    proof_selectors: HashSet<[u8; 4]>,
}

impl StorageProofDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut proof_selectors = HashSet::new();
        proof_selectors.insert([0x9d, 0x69, 0x6c, 0x0e]); // verifyProof()
        proof_selectors.insert([0xe4, 0x95, 0xf7, 0x47]); // verifyMerkleProof()
        proof_selectors.insert([0x3e, 0xb8, 0x73, 0x1a]); // withdraw() (L2 pattern)
        
        Self { bytecode, proof_selectors }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_storage_proof_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_unchecked_proof());
        vulnerabilities.extend(self.detect_storage_root_issues());
        vulnerabilities.extend(self.detect_proof_replay());

        vulnerabilities
    }

    fn detect_unchecked_proof(&self) -> Vec<StorageProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: KECCAK256 for Merkle without result validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x20 && // KECCAK256
               self.is_in_proof_context(i) {
                
                // Check if hash comparison happens
                let has_eq_check = self.has_comparison_after(i);
                
                if !has_eq_check {
                    vulnerabilities.push(StorageProofVulnerability {
                        vulnerability_type: StorageProofIssueType::UncheckedProofVerification,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "Merkle proof computed but not validated".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker submits invalid proof\n\
                            2. Contract computes Merkle root but doesn't check\n\
                            3. Invalid withdrawal/claim proceeds\n\
                            4. Bridge/protocol funds drained\n\n\
                            Fix: require(computedRoot == expectedRoot)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_storage_root_issues(&self) -> Vec<StorageProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Storage proof without block hash verification
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_in_proof_context(i) {
                // Look for BLOCKHASH check
                let has_blockhash_check = self.has_blockhash_verification(i);
                
                if !has_blockhash_check {
                    vulnerabilities.push(StorageProofVulnerability {
                        vulnerability_type: StorageProofIssueType::StorageRootNotVerified,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.75,
                        description: "Storage root not verified against block hash".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker provides storage proof from any block\n\
                            2. No verification of block hash\n\
                            3. Can prove fake state from attacker-controlled fork\n\
                            4. Complete bypass of cross-chain security\n\n\
                            Fix: Verify stateRoot against blockhash(blockNumber)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_proof_replay(&self) -> Vec<StorageProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Proof verification without uniqueness tracking
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_in_proof_context(i) {
                let has_nonce_or_uniqueness = self.has_uniqueness_check(i);
                
                if !has_nonce_or_uniqueness {
                    vulnerabilities.push(StorageProofVulnerability {
                        vulnerability_type: StorageProofIssueType::ProofReplayAttack,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Storage proof can be replayed".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User withdraws with proof P\n\
                            2. Attacker captures proof P\n\
                            3. Replays same proof for double-withdrawal\n\
                            4. Bridge drained via replay\n\n\
                            Fix: Track used proofs: proofUsed[proofHash] = true",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_storage_proof_contract(&self) -> bool {
        // Check for proof verification patterns
        for selector in &self.proof_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        // Or multiple KECCAK256 (Merkle tree pattern)
        self.bytecode.iter().filter(|&&b| b == 0x20).count() >= 3
    }

    fn is_in_proof_context(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(50)..pos.saturating_add(50).min(self.bytecode.len()) {
            if i + 4 <= self.bytecode.len() {
                for selector in &self.proof_selectors {
                    if &self.bytecode[i..i+4] == selector {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_comparison_after(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(10).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x14 { // EQ
                return true;
            }
        }
        false
    }

    fn has_blockhash_verification(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(50)..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x40 { // BLOCKHASH
                return true;
            }
        }
        false
    }

    fn has_uniqueness_check(&self, pos: usize) -> bool {
        // Look for SLOAD/SSTORE pattern (tracking used proofs)
        let mut has_sload = false;
        let mut has_sstore = false;
        for i in pos..pos.saturating_add(100).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { has_sload = true; }
            if self.bytecode[i] == 0x55 { has_sstore = true; }
        }
        has_sload && has_sstore
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchecked_merkle_proof() {
        let bytecode = vec![
            0x9d, 0x69, 0x6c, 0x0e, // verifyProof selector
            0x20, // KECCAK256
            // Missing EQ check
            0x55, // SSTORE (proceed)
        ];
        
        let detector = StorageProofDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty());
    }
}
