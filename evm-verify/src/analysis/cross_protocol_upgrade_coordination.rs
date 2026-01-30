/// Cross-Protocol Upgrade Coordination Failure Detector
///
/// Detects upgrade timing mismatches between integrated protocols.
/// Risk: All upgradeable integrated protocols
/// Attack: Aave upgrades v2→v3 but Yearn vaults still use v2 interface
/// Real issues: Compound v2→v3 caused multiple integrator breakages

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolUpgradeCoordinationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub coordination_failure: UpgradeCoordinationFailure,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpgradeCoordinationFailure {
    InterfaceMismatchAfterUpgrade,
    UncoordinatedUpgradeTiming,
    BackwardIncompatibilityExploit,
    UpgradeStateDesynchronization,
    DependencyVersionConflict,
}

pub struct CrossProtocolUpgradeCoordinationAnalyzer;

impl CrossProtocolUpgradeCoordinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolUpgradeCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_interface_mismatch_risk(bytecode) {
            vulnerabilities.push(CrossProtocolUpgradeCoordinationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Protocol upgrade changes interface used by dependent protocols".to_string(),
                location: "Protocol interface".to_string(),
                coordination_failure: UpgradeCoordinationFailure::InterfaceMismatchAfterUpgrade,
                impact: "Aave v3 changes function signatures breaking Yearn vault integrations".to_string(),
            });
        }

        if self.has_uncoordinated_upgrade_timing(bytecode) {
            vulnerabilities.push(CrossProtocolUpgradeCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Protocol upgrades without notifying/updating dependencies".to_string(),
                location: "Upgrade execution".to_string(),
                coordination_failure: UpgradeCoordinationFailure::UncoordinatedUpgradeTiming,
                impact: "Protocol A upgrades creating exploit window before Protocol B updates".to_string(),
            });
        }

        if self.has_backward_incompatibility_exploit(bytecode) {
            vulnerabilities.push(CrossProtocolUpgradeCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Upgrade breaks backward compatibility exploitable by attackers".to_string(),
                location: "Version compatibility".to_string(),
                coordination_failure: UpgradeCoordinationFailure::BackwardIncompatibilityExploit,
                impact: "Old integrations call deprecated functions with unsafe fallback behavior".to_string(),
            });
        }

        if self.has_upgrade_state_desync(bytecode) {
            vulnerabilities.push(CrossProtocolUpgradeCoordinationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "State assumptions differ between old and new protocol versions".to_string(),
                location: "State migration".to_string(),
                coordination_failure: UpgradeCoordinationFailure::UpgradeStateDesynchronization,
                impact: "Protocol A assumes new state format, Protocol B still uses old format".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_interface_mismatch_risk(&self, bytecode: &[u8]) -> bool {
        // Upgrade proxy without interface version checking
        bytecode.windows(60).any(|window| {
            window.contains(&0x55) && // Implementation update
            window.contains(&0xf1) && // External calls to this protocol
            !window.contains(&0x54) && // No version tracking
            !window.contains(&0x14)    // No interface compatibility check
        })
    }

    fn has_uncoordinated_upgrade_timing(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0x55) && // Upgrade storage write
            !window.iter().filter(|&&op| op == 0xf1).count() >= 2 // No multi-protocol notification
        })
    }

    fn has_backward_incompatibility_exploit(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0x3b) && // EXTCODESIZE (interface check)
            window.contains(&0xf1) && // External call
            !window.contains(&0x54)   // No version compatibility storage
        })
    }

    fn has_upgrade_state_desync(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x55) && // State write (upgrade)
            window.contains(&0xf1) && // Cross-protocol query
            !window.contains(&0x20)   // No state format verification
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolUpgradeCoordinationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolUpgradeCoordination,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Upgrade Coordination: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement upgrade coordination, version tracking, and backward compatibility", vuln.location),
        }).collect()
    }
}
