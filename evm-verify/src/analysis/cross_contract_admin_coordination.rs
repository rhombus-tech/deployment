/// Cross-Contract Admin Coordination Detector
///
/// Detects failures in coordinating admin operations across dependent protocols.
/// Risk: Governance-dependent protocols ($100B+ TVL)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractAdminCoordinationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub coordination_failure: AdminCoordinationFailure,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AdminCoordinationFailure {
    UncoordinatedUpgrades,
    AsynchronousAdminChanges,
    DependentParameterMismatch,
    EmergencyActionCascade,
}

pub struct CrossContractAdminCoordinationAnalyzer;

impl CrossContractAdminCoordinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractAdminCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_uncoordinated_upgrades(bytecode) {
            vulnerabilities.push(CrossContractAdminCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Protocol upgrade doesn't coordinate with dependent protocols".to_string(),
                location: "Upgrade logic".to_string(),
                coordination_failure: AdminCoordinationFailure::UncoordinatedUpgrades,
                impact: "Upgrade breaks dependent protocol integrations".to_string(),
            });
        }

        if self.has_parameter_mismatch_risk(bytecode) {
            vulnerabilities.push(CrossContractAdminCoordinationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Admin parameter changes without checking dependent protocol compatibility".to_string(),
                location: "Parameter update".to_string(),
                coordination_failure: AdminCoordinationFailure::DependentParameterMismatch,
                impact: "Parameter changes break cross-protocol assumptions".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_uncoordinated_upgrades(&self, bytecode: &[u8]) -> bool {
        let upgrade_sig = &[0x3f, 0x4b, 0xa8, 0x3a]; // upgradeToAndCall()
        bytecode.windows(4).any(|w| w == upgrade_sig) &&
        !bytecode.contains(&0xfa) // No external coordination check
    }

    fn has_parameter_mismatch_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0x55) && // SSTORE (parameter update)
            window.contains(&0x33) && // CALLER (admin check)
            !window.contains(&0xfa)   // No external protocol check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractAdminCoordinationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractAdminCoordination,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Admin Coordination: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement coordination checks before admin actions", vuln.location),
        }).collect()
    }
}
