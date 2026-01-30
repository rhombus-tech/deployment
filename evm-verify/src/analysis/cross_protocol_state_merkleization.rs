/// Cross-Protocol State Merkleization Inconsistency Detector
///
/// Detects state Merkle root inconsistencies across protocols.
/// Risk: All proof-based systems, ZK rollups
/// Attack: Same state, different Merkle roots break proofs

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolStateMerkleizationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub inconsistency_type: MerkleInconsistencyType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MerkleInconsistencyType {
    StateRootMismatch,
    ProofFormatIncompatibility,
    TreeStructureConflict,
}

pub struct CrossProtocolStateMerkleizationAnalyzer;

impl CrossProtocolStateMerkleizationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolStateMerkleizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_state_root_mismatch(bytecode) {
            vulnerabilities.push(CrossProtocolStateMerkleizationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Protocols compute different Merkle roots for same state".to_string(),
                location: "State root calculation".to_string(),
                inconsistency_type: MerkleInconsistencyType::StateRootMismatch,
                impact: "Protocol A accepts proof, Protocol B rejects same proof".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_state_root_mismatch(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x20) && // SHA3 (merkle root)
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-protocol
            !window.contains(&0x14) // No root consistency check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolStateMerkleizationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolStateMerkleization,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol State Merkleization: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Standardize Merkle tree construction across protocols", vuln.location),
        }).collect()
    }
}
