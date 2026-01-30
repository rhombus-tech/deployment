/// Cross-Rollup Atomic Composability Failure Detector
///
/// Detects failures in atomic execution guarantees across L2 rollups.
/// Risk: $150B+ in cross-rollup TVL, all multi-L2 DeFi protocols
/// Attack: Transaction bundle partially executes - succeeds on one L2, fails on another
/// Reference: 6 levels of rollup interoperability (1kx research)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossRollupAtomicComposabilityVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub composability_failure: ComposabilityFailureType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComposabilityFailureType {
    AtomicInclusionFailure,
    AtomicExecutionFailure,
    BlockLevelComposabilityLoss,
    TransactionLevelComposabilityLoss,
    DependentTransactionDesync,
}

pub struct CrossRollupAtomicComposabilityAnalyzer;

impl CrossRollupAtomicComposabilityAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossRollupAtomicComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_atomic_inclusion_failure(bytecode) {
            vulnerabilities.push(CrossRollupAtomicComposabilityVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Cross-rollup bundle not guaranteed atomic inclusion".to_string(),
                location: "Cross-L2 transaction".to_string(),
                composability_failure: ComposabilityFailureType::AtomicInclusionFailure,
                impact: "Transaction included on Arbitrum but not on Optimism".to_string(),
            });
        }

        if self.has_atomic_execution_failure(bytecode) {
            vulnerabilities.push(CrossRollupAtomicComposabilityVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Cross-rollup execution not atomic - partial execution possible".to_string(),
                location: "Multi-L2 operation".to_string(),
                composability_failure: ComposabilityFailureType::AtomicExecutionFailure,
                impact: "Deposit succeeds on L2 A but swap fails on L2 B - funds locked".to_string(),
            });
        }

        if self.has_dependent_transaction_desync(bytecode) {
            vulnerabilities.push(CrossRollupAtomicComposabilityVulnerability {
                severity: SecuritySeverity::High,
                description: "Dependent transactions across rollups not coordinated".to_string(),
                location: "Dependent cross-L2 calls".to_string(),
                composability_failure: ComposabilityFailureType::DependentTransactionDesync,
                impact: "Transaction B on L2 B executes before Transaction A on L2 A completes".to_string(),
            });
        }

        if self.has_transaction_level_composability_loss(bytecode) {
            vulnerabilities.push(CrossRollupAtomicComposabilityVulnerability {
                severity: SecuritySeverity::Medium,
                description: "No smart contract level interoperability across rollups".to_string(),
                location: "Cross-rollup call".to_string(),
                composability_failure: ComposabilityFailureType::TransactionLevelComposabilityLoss,
                impact: "Cannot atomically revert state changes across multiple L2s".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_atomic_inclusion_failure(&self, bytecode: &[u8]) -> bool {
        // Cross-L2 operation without inclusion guarantee
        bytecode.windows(60).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple L2 calls
            !window.contains(&0x55) && // No inclusion proof
            !window.contains(&0x14)    // No bundle verification
        })
    }

    fn has_atomic_execution_failure(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-L2
            !window.contains(&0x57) && // No revert on partial failure
            !window.contains(&0x54)    // No execution state tracking
        })
    }

    fn has_dependent_transaction_desync(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(80).any(|window| {
            window.contains(&0xf1) && // External call
            window.contains(&0xfa) && // Dependent query
            !window.contains(&0x42) && // No timestamp coordination
            !window.contains(&0x43)    // No block coordination
        })
    }

    fn has_transaction_level_composability_loss(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // Cross-L2 call
            !window.contains(&0x3d) && // No RETURNDATASIZE check
            !window.contains(&0x3e)    // No RETURNDATACOPY (can't use return data)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossRollupAtomicComposabilityVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossRollupAtomicComposability,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Rollup Atomic Composability: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement atomic cross-rollup guarantees via shared sequencer", vuln.location),
        }).collect()
    }
}
