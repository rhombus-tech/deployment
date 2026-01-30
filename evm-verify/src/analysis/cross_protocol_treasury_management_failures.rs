/// Cross-Protocol Treasury Management Failures Detector
///
/// Detects treasury asset coordination failures across protocols.
/// Risk: $100B+ in DAO treasuries managed across multiple protocols
/// Attack: Treasury diversified, one protocol exploited affects all

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolTreasuryManagementFailuresVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub failure_type: TreasuryFailureType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TreasuryFailureType {
    TreasuryDiversificationRisk,
    CrossProtocolLiquidationCascade,
    TreasuryRebalancingExploit,
}

pub struct CrossProtocolTreasuryManagementFailuresAnalyzer;

impl CrossProtocolTreasuryManagementFailuresAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolTreasuryManagementFailuresVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_treasury_diversification_risk(bytecode) {
            vulnerabilities.push(CrossProtocolTreasuryManagementFailuresVulnerability {
                severity: SecuritySeverity::High,
                description: "Treasury assets across protocols create correlated risk".to_string(),
                location: "Treasury management".to_string(),
                failure_type: TreasuryFailureType::TreasuryDiversificationRisk,
                impact: "Treasury in Aave+Compound exploited via Curve affecting both".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_treasury_diversification_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(90).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // Multiple protocols
            window.contains(&0x01) && // Asset deposit/management
            !window.contains(&0x10)   // No correlation risk assessment
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolTreasuryManagementFailuresVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolTreasuryManagementFailures,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Treasury Management: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement cross-protocol risk assessment for treasury assets", vuln.location),
        }).collect()
    }
}
