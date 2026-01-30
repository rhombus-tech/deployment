/// Cross-Rollup Sequencer Centralization Risk Detector
///
/// Detects centralized sequencer risks affecting multiple rollups.
/// Risk: All L2 sequencers (Arbitrum, Optimism, Base, etc.)
/// Attack: Centralized sequencer censors or reorders across multiple L2s

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossRollupSequencerCentralizationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub centralization_risk: SequencerCentralizationRisk,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SequencerCentralizationRisk {
    CrossRollupCensorship,
    SequencerCoordinatedReorder,
    SinglePointOfFailure,
    CentralizedSequencerDependency,
    MEVExtractionAcrossRollups,
}

pub struct CrossRollupSequencerCentralizationAnalyzer;

impl CrossRollupSequencerCentralizationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossRollupSequencerCentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_cross_rollup_censorship_risk(bytecode) {
            vulnerabilities.push(CrossRollupSequencerCentralizationVulnerability {
                severity: SecuritySeverity::High,
                description: "Centralized sequencer can censor transactions across multiple rollups".to_string(),
                location: "Cross-rollup operation".to_string(),
                centralization_risk: SequencerCentralizationRisk::CrossRollupCensorship,
                impact: "Same entity controls sequencers on Arbitrum + Optimism enabling censorship".to_string(),
            });
        }

        if self.has_coordinated_reorder_risk(bytecode) {
            vulnerabilities.push(CrossRollupSequencerCentralizationVulnerability {
                severity: SecuritySeverity::High,
                description: "Sequencer can coordinate transaction ordering across rollups".to_string(),
                location: "Transaction ordering".to_string(),
                centralization_risk: SequencerCentralizationRisk::SequencerCoordinatedReorder,
                impact: "Sequencer reorders on L2 A to benefit transaction on L2 B".to_string(),
            });
        }

        if self.has_single_point_of_failure(bytecode) {
            vulnerabilities.push(CrossRollupSequencerCentralizationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Single sequencer controls multiple critical rollups".to_string(),
                location: "Sequencer dependency".to_string(),
                centralization_risk: SequencerCentralizationRisk::SinglePointOfFailure,
                impact: "Sequencer downtime affects multiple rollups simultaneously".to_string(),
            });
        }

        if self.has_mev_extraction_across_rollups(bytecode) {
            vulnerabilities.push(CrossRollupSequencerCentralizationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Sequencer extracts MEV across multiple rollups atomically".to_string(),
                location: "MEV extraction".to_string(),
                centralization_risk: SequencerCentralizationRisk::MEVExtractionAcrossRollups,
                impact: "Sequencer sandwiches user across Arbitrum and Base simultaneously".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_cross_rollup_censorship_risk(&self, bytecode: &[u8]) -> bool {
        // Operations across multiple L2s without decentralization check
        bytecode.windows(80).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple L2 calls
            !window.contains(&0x54) && // No sequencer decentralization check
            !window.contains(&0x46)    // No chain ID diversity verification
        })
    }

    fn has_coordinated_reorder_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x42) && // Timestamp dependency
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-rollup
            !window.contains(&0x43) // No block number isolation
        })
    }

    fn has_single_point_of_failure(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // 3+ rollups
            !window.contains(&0x54) // No sequencer redundancy check
        })
    }

    fn has_mev_extraction_across_rollups(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(100).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple rollups
            window.contains(&0x02) && // Profit calculation
            !window.contains(&0x10)   // No MEV protection
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossRollupSequencerCentralizationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossRollupSequencerCentralization,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Rollup Sequencer Centralization: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Use decentralized sequencers or diversify rollup selection", vuln.location),
        }).collect()
    }
}
