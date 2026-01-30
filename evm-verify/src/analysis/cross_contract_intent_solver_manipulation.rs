/// Cross-Contract Intent Solver Manipulation Detector
///
/// Detects malicious solver behavior in intent-based protocols across chains.
/// Risk: CoW Protocol, UniswapX, 1inch Fusion ($5B+ in intent volume)
/// Attack: Solver provides false quotes on one chain, drains on another

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractIntentSolverManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: IntentSolverManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IntentSolverManipulationType {
    FalseQuoteAcrossChains,
    SolverFrontrunning,
    PartialIntentFulfillment,
    CrossChainIntentRaceCondition,
    SolverNetworkCollusion,
}

pub struct CrossContractIntentSolverManipulationAnalyzer;

impl CrossContractIntentSolverManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractIntentSolverManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_false_quote_risk(bytecode) {
            vulnerabilities.push(CrossContractIntentSolverManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Intent solver can provide false quotes across chains".to_string(),
                location: "Intent fulfillment".to_string(),
                manipulation_type: IntentSolverManipulationType::FalseQuoteAcrossChains,
                impact: "Solver exploits price difference between chains to drain user".to_string(),
            });
        }

        if self.has_partial_fulfillment_risk(bytecode) {
            vulnerabilities.push(CrossContractIntentSolverManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Solver can partially fulfill intent leaving user exposed".to_string(),
                location: "Intent validation".to_string(),
                manipulation_type: IntentSolverManipulationType::PartialIntentFulfillment,
                impact: "Partial execution on one chain, full execution on another".to_string(),
            });
        }

        if self.has_cross_chain_race(bytecode) {
            vulnerabilities.push(CrossContractIntentSolverManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Intent execution race condition across chains".to_string(),
                location: "Cross-chain coordination".to_string(),
                manipulation_type: IntentSolverManipulationType::CrossChainIntentRaceCondition,
                impact: "Intent executed on both chains due to race condition".to_string(),
            });
        }

        if self.has_solver_frontrun_risk(bytecode) {
            vulnerabilities.push(CrossContractIntentSolverManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Solver can frontrun user intent across protocols".to_string(),
                location: "Intent submission".to_string(),
                manipulation_type: IntentSolverManipulationType::SolverFrontrunning,
                impact: "Solver sees intent and frontruns on destination chain".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_false_quote_risk(&self, bytecode: &[u8]) -> bool {
        // Intent quote without cross-chain price verification
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // External call (intent fulfillment)
            window.contains(&0x02) && // Price calculation
            !window.contains(&0xfa)   // No external price check
        })
    }

    fn has_partial_fulfillment_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // External call
            !window.contains(&0x14) && // No completion check
            !window.contains(&0x57)   // No revert on failure
        })
    }

    fn has_cross_chain_race(&self, bytecode: &[u8]) -> bool {
        // Multiple external calls without nonce or replay protection
        bytecode.windows(60).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple chains
            !window.contains(&0x54) && // No nonce check
            !window.contains(&0x55)    // No state update
        })
    }

    fn has_solver_frontrun_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // External call
            !window.contains(&0x42) && // No timestamp lock
            !window.contains(&0x43)    // No block number lock
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractIntentSolverManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractIntentSolverManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Intent Solver Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement cross-chain quote verification and atomic fulfillment", vuln.location),
        }).collect()
    }
}
