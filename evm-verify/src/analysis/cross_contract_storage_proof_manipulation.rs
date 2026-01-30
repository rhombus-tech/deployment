/// Cross-Contract Storage Proof Manipulation Detector
///
/// Detects vulnerabilities in Merkle/storage proof verification across protocols.
/// Risk: All proof-based bridges, state verification systems
/// Real exploits: Nomad Bridge ($190M) - proof validation failure

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractStorageProofManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: ProofManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProofManipulationType {
    UncheckedProofRoot,
    ProofReplay,
    InvalidMerkleProof,
    StateRootMismatch,
}

pub struct CrossContractStorageProofManipulationAnalyzer;

impl CrossContractStorageProofManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractStorageProofManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_unchecked_proof_root(bytecode) {
            vulnerabilities.push(CrossContractStorageProofManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Storage proof accepted without root verification".to_string(),
                location: "Proof verification".to_string(),
                manipulation_type: ProofManipulationType::UncheckedProofRoot,
                impact: "False proofs can be accepted enabling cross-protocol state manipulation".to_string(),
            });
        }

        if self.has_proof_replay_risk(bytecode) {
            vulnerabilities.push(CrossContractStorageProofManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Storage proofs can be replayed across protocols".to_string(),
                location: "Proof validation".to_string(),
                manipulation_type: ProofManipulationType::ProofReplay,
                impact: "Old proofs reused to manipulate cross-protocol state".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_unchecked_proof_root(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0x20) && // SHA3
            !window.contains(&0x14)   // No EQ check for root
        })
    }

    fn has_proof_replay_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0x20) && // Proof hashing
            !window.contains(&0x55) && // No nonce storage
            !window.contains(&0x42)   // No timestamp check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractStorageProofManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractStorageProofManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Storage Proof Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement strict proof verification and replay protection", vuln.location),
        }).collect()
    }
}
