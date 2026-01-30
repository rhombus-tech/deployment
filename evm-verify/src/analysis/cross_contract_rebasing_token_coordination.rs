/// Cross-Contract Rebasing Token Coordination Detector
///
/// Detects rebase event propagation failures across integrated protocols.
/// Risk: Ampleforth, OHM-style rebasing tokens ($5B+)
/// Attack: Rebase in Protocol A doesn't update Protocol B balances

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractRebasingTokenCoordinationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub coordination_failure: RebasingCoordinationFailure,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RebasingCoordinationFailure {
    RebaseEventNotPropagated,
    BalanceSnapshotStale,
    RebaseMultiplierDesync,
    NegativeRebaseCascade,
    RebaseTimingExploit,
}

pub struct CrossContractRebasingTokenCoordinationAnalyzer;

impl CrossContractRebasingTokenCoordinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractRebasingTokenCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_rebase_event_propagation_failure(bytecode) {
            vulnerabilities.push(CrossContractRebasingTokenCoordinationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Rebase event not propagated to dependent protocols".to_string(),
                location: "Rebase execution".to_string(),
                coordination_failure: RebasingCoordinationFailure::RebaseEventNotPropagated,
                impact: "Ampleforth rebases but Aave collateral value not updated".to_string(),
            });
        }

        if self.has_balance_snapshot_stale(bytecode) {
            vulnerabilities.push(CrossContractRebasingTokenCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Protocol uses stale pre-rebase balance snapshot".to_string(),
                location: "Balance query".to_string(),
                coordination_failure: RebasingCoordinationFailure::BalanceSnapshotStale,
                impact: "Protocol A caches balance, rebase happens, Protocol B uses old balance".to_string(),
            });
        }

        if self.has_rebase_multiplier_desync(bytecode) {
            vulnerabilities.push(CrossContractRebasingTokenCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Rebase multiplier differs across protocols".to_string(),
                location: "Multiplier calculation".to_string(),
                coordination_failure: RebasingCoordinationFailure::RebaseMultiplierDesync,
                impact: "Different protocols see different balances for same rebasing token".to_string(),
            });
        }

        if self.has_negative_rebase_cascade(bytecode) {
            vulnerabilities.push(CrossContractRebasingTokenCoordinationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Negative rebase triggers cascading liquidations".to_string(),
                location: "Negative rebase handling".to_string(),
                coordination_failure: RebasingCoordinationFailure::NegativeRebaseCascade,
                impact: "Negative rebase reduces collateral triggering liquidations across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_rebase_event_propagation_failure(&self, bytecode: &[u8]) -> bool {
        // Rebase without cross-protocol notification
        bytecode.windows(60).any(|window| {
            window.contains(&0x02) && // Rebase calculation (multiplier)
            window.contains(&0x55) && // State update
            !window.iter().filter(|&&op| op == 0xf1).count() >= 2 // No multi-protocol notification
        })
    }

    fn has_balance_snapshot_stale(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0x54) && // Balance read (cached)
            !window.contains(&0x42) && // No timestamp check
            window.contains(&0xf1)     // Used in cross-protocol operation
        })
    }

    fn has_rebase_multiplier_desync(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x02) && // Multiplier calculation
            window.iter().filter(|&&op| op == 0xfa).count() >= 2 && // Multiple protocol queries
            !window.contains(&0x14) // No multiplier consistency check
        })
    }

    fn has_negative_rebase_cascade(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0x03) && // Balance reduction (negative rebase)
            window.contains(&0xf1) && // External call
            !window.contains(&0x10)   // No health factor recalculation
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractRebasingTokenCoordinationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractRebasingTokenCoordination,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Rebasing Token Coordination: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement rebase event propagation and real-time balance queries", vuln.location),
        }).collect()
    }
}
