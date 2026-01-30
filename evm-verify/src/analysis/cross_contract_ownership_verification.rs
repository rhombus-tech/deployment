/// Cross-Contract Ownership Verification Failure Detector
///
/// Detects ownership state consistency failures across protocols.
/// Risk: NFT-Fi, ownership-dependent protocols
/// Attack: Transfer ownership between protocols mid-operation

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractOwnershipVerificationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub verification_failure: OwnershipVerificationFailure,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OwnershipVerificationFailure {
    StaleOwnershipCheck,
    CrossProtocolOwnershipRace,
    OwnershipTransferExploitation,
    MultiProtocolOwnershipConflict,
}

pub struct CrossContractOwnershipVerificationAnalyzer;

impl CrossContractOwnershipVerificationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractOwnershipVerificationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_stale_ownership_check(bytecode) {
            vulnerabilities.push(CrossContractOwnershipVerificationVulnerability {
                severity: SecuritySeverity::High,
                description: "Ownership verified in one protocol, used without re-check in another".to_string(),
                location: "Ownership verification".to_string(),
                verification_failure: OwnershipVerificationFailure::StaleOwnershipCheck,
                impact: "NFT transferred between ownership check and usage".to_string(),
            });
        }

        if self.has_ownership_race(bytecode) {
            vulnerabilities.push(CrossContractOwnershipVerificationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Ownership can change during cross-protocol operation".to_string(),
                location: "Ownership race condition".to_string(),
                verification_failure: OwnershipVerificationFailure::CrossProtocolOwnershipRace,
                impact: "Ownership transfer exploits time gap between protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_stale_ownership_check(&self, bytecode: &[u8]) -> bool {
        let owner_sig = &[0x8d, 0xa5, 0xcb, 0x5b]; // ownerOf()
        bytecode.windows(4).any(|w| w == owner_sig) &&
        bytecode.windows(60).any(|window| {
            window.contains(&0xfa) && // Ownership query
            window.contains(&0xf1) && // Later external call
            !window.windows(4).any(|w| w == owner_sig) // No re-check
        })
    }

    fn has_ownership_race(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // Ownership query
            !window.contains(&0x42) && // No timestamp lock
            window.contains(&0xf1)    // External call
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractOwnershipVerificationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractOwnershipVerification,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Ownership Verification: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Re-verify ownership before each use", vuln.location),
        }).collect()
    }
}
