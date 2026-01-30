/// Cross-Contract Preconfirmation Coordination Detector
///
/// Detects based rollup preconfirmation risks across protocols.
/// Risk: Based rollups (emerging $50B+ potential), Taiko, etc.
/// Attack: Preconf reorg cascades across dependent protocols

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractPreconfirmationCoordinationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub preconf_risk: PreconfirmationRisk,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PreconfirmationRisk {
    PreconfReorg,
    CrossProtocolPreconfDependency,
    UnconfirmedStateUsage,
    PreconfInclusionFailure,
}

pub struct CrossContractPreconfirmationCoordinationAnalyzer;

impl CrossContractPreconfirmationCoordinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractPreconfirmationCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_preconf_dependency(bytecode) {
            vulnerabilities.push(CrossContractPreconfirmationCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Protocol relies on preconfirmations without finality guarantee".to_string(),
                location: "Preconf handling".to_string(),
                preconf_risk: PreconfirmationRisk::CrossProtocolPreconfDependency,
                impact: "Preconf reorg breaks cross-protocol state assumptions".to_string(),
            });
        }

        if self.has_unconfirmed_state_usage(bytecode) {
            vulnerabilities.push(CrossContractPreconfirmationCoordinationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Unconfirmed state used in cross-protocol operations".to_string(),
                location: "State usage".to_string(),
                preconf_risk: PreconfirmationRisk::UnconfirmedStateUsage,
                impact: "State reversion cascades across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_preconf_dependency(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // External call
            !window.contains(&0x43) && // No block confirmation check
            !window.contains(&0x42)   // No timestamp delay
        })
    }

    fn has_unconfirmed_state_usage(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // State query
            window.contains(&0x55) && // State write
            !window.contains(&0x43)   // No confirmation depth
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractPreconfirmationCoordinationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractPreconfirmationCoordination,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Preconfirmation Coordination: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Wait for finality before cross-protocol operations", vuln.location),
        }).collect()
    }
}
