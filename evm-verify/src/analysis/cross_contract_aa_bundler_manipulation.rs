/// Cross-Contract Account Abstraction Bundler Manipulation Detector
///
/// Detects AA bundler reordering UserOperations across protocols.
/// Risk: Growing ERC-4337 adoption ($10B+ projected)
/// Attack: Bundler reorders UserOps for profit across integrated protocols

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractAABundlerManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: BundlerManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BundlerManipulationType {
    UserOpReorderingForProfit,
    CrossProtocolSandwich,
    BundlerFrontrunning,
    SelectiveBundleInclusion,
    BundlerCollusion,
}

pub struct CrossContractAABundlerManipulationAnalyzer;

impl CrossContractAABundlerManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractAABundlerManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_user_op_reordering_risk(bytecode) {
            vulnerabilities.push(CrossContractAABundlerManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Bundler can reorder UserOperations for profit".to_string(),
                location: "UserOp bundling".to_string(),
                manipulation_type: BundlerManipulationType::UserOpReorderingForProfit,
                impact: "Bundler reorders user swaps to extract MEV across protocols".to_string(),
            });
        }

        if self.has_cross_protocol_sandwich(bytecode) {
            vulnerabilities.push(CrossContractAABundlerManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Bundler sandwiches UserOps across multiple protocols".to_string(),
                location: "Bundle execution".to_string(),
                manipulation_type: BundlerManipulationType::CrossProtocolSandwich,
                impact: "Bundler frontruns on Uniswap, backruns on SushiSwap in same bundle".to_string(),
            });
        }

        if self.has_bundler_frontrunning(bytecode) {
            vulnerabilities.push(CrossContractAABundlerManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Bundler sees UserOps and frontruns across protocols".to_string(),
                location: "Mempool monitoring".to_string(),
                manipulation_type: BundlerManipulationType::BundlerFrontrunning,
                impact: "Bundler copies profitable UserOp strategy before including user's operation".to_string(),
            });
        }

        if self.has_selective_bundle_inclusion(bytecode) {
            vulnerabilities.push(CrossContractAABundlerManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Bundler selectively includes/excludes UserOps for advantage".to_string(),
                location: "Bundle composition".to_string(),
                manipulation_type: BundlerManipulationType::SelectiveBundleInclusion,
                impact: "Bundler excludes competing UserOps to maximize own profit".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_user_op_reordering_risk(&self, bytecode: &[u8]) -> bool {
        // Multiple UserOps without ordering protection
        bytecode.windows(80).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // Multiple UserOps
            !window.contains(&0x54) && // No nonce ordering enforcement
            !window.contains(&0x42)    // No timestamp ordering
        })
    }

    fn has_cross_protocol_sandwich(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(100).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // Frontrun + user + backrun
            window.contains(&0x02) && // Profit calculation
            !window.contains(&0x10)   // No sandwich protection
        })
    }

    fn has_bundler_frontrunning(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x37) && // CALLDATACOPY (user op data)
            window.contains(&0xf1) && // External call
            !window.contains(&0x20)   // No commitment/blinding
        })
    }

    fn has_selective_bundle_inclusion(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x56) && // JUMP (conditional inclusion)
            window.contains(&0xf1) && // UserOp call
            !window.contains(&0x54)   // No fairness tracking
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractAABundlerManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractAABundlerManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract AA Bundler Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement bundler commitments, ordering constraints, and MEV protection", vuln.location),
        }).collect()
    }
}
