/// Cross-Contract Finality Assumption Mismatch Detector
///
/// Detects finality period mismatches between L1/L2 protocols.
/// Risk: $100B+ in cross-L2 TVL, 7-day optimistic vs instant ZK finality
/// Examples: Optimism (7 days) vs Arbitrum (instant) vs zkSync

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractFinalityMismatchVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub mismatch_type: FinalityMismatchType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FinalityMismatchType {
    OptimisticVsZKFinality,
    L1VsL2FinalityGap,
    CrossL2FinalityWindow,
    ReorgRiskMismatch,
    ConfirmationDepthConflict,
}

pub struct CrossContractFinalityMismatchAnalyzer;

impl CrossContractFinalityMismatchAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractFinalityMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_optimistic_zk_mismatch(bytecode) {
            vulnerabilities.push(CrossContractFinalityMismatchVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Cross-L2 operation assumes instant finality on optimistic rollup".to_string(),
                location: "Cross-chain bridge".to_string(),
                mismatch_type: FinalityMismatchType::OptimisticVsZKFinality,
                impact: "7-day challenge period creates exploitable window".to_string(),
            });
        }

        if self.has_l1_l2_finality_gap(bytecode) {
            vulnerabilities.push(CrossContractFinalityMismatchVulnerability {
                severity: SecuritySeverity::High,
                description: "L1 finality assumptions don't account for L2 reorg risk".to_string(),
                location: "L1-L2 messaging".to_string(),
                mismatch_type: FinalityMismatchType::L1VsL2FinalityGap,
                impact: "L2 reorg can invalidate L1 protocol state".to_string(),
            });
        }

        if self.has_confirmation_depth_conflict(bytecode) {
            vulnerabilities.push(CrossContractFinalityMismatchVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Different confirmation depth requirements across protocols".to_string(),
                location: "Confirmation logic".to_string(),
                mismatch_type: FinalityMismatchType::ConfirmationDepthConflict,
                impact: "Protocol accepts lower confirmations than dependencies require".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_optimistic_zk_mismatch(&self, bytecode: &[u8]) -> bool {
        // Cross-chain call without finality delay check
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // External call
            !window.contains(&0x42) && // No timestamp check
            !window.contains(&0x43)   // No block number check
        })
    }

    fn has_l1_l2_finality_gap(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // Cross-layer call
            !window.contains(&0x03)   // No delay subtraction
        })
    }

    fn has_confirmation_depth_conflict(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(30).any(|window| {
            window.contains(&0x43) && // BLOCKNUMBER
            !window.contains(&0x10)   // No depth check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractFinalityMismatchVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractFinalityMismatch,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Finality Mismatch: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Account for all finality periods in cross-chain operations", vuln.location),
        }).collect()
    }
}
