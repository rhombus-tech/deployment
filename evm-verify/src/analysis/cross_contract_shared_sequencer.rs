/// Cross-Contract Shared Sequencer Exploitation Detector
///
/// Detects vulnerabilities from shared sequencers (Espresso, Astria).
/// Risk: Emerging shared sequencer networks, atomic cross-L2 attacks
/// Attack: Sequencer coordinates state manipulation across multiple rollups

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractSharedSequencerVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub sequencer_risk: SharedSequencerRisk,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SharedSequencerRisk {
    AtomicCrossL2Manipulation,
    SequencerCensorshipCascade,
    CrossRollupMEV,
    SharedStateExploitation,
}

pub struct CrossContractSharedSequencerAnalyzer;

impl CrossContractSharedSequencerAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractSharedSequencerVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_atomic_cross_l2_risk(bytecode) {
            vulnerabilities.push(CrossContractSharedSequencerVulnerability {
                severity: SecuritySeverity::High,
                description: "Shared sequencer can atomically manipulate state across L2s".to_string(),
                location: "Cross-L2 operation".to_string(),
                sequencer_risk: SharedSequencerRisk::AtomicCrossL2Manipulation,
                impact: "Sequencer coordinates attack across multiple rollups simultaneously".to_string(),
            });
        }

        if self.has_shared_state_exploitation(bytecode) {
            vulnerabilities.push(CrossContractSharedSequencerVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Shared sequencer state creates cross-rollup dependency".to_string(),
                location: "Sequencer dependency".to_string(),
                sequencer_risk: SharedSequencerRisk::SharedStateExploitation,
                impact: "State consistency assumptions broken across rollups".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_atomic_cross_l2_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple L2 calls
            !window.contains(&0x43) // No block number isolation
        })
    }

    fn has_shared_state_exploitation(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // External call
            window.contains(&0x54) && // Shared state load
            !window.contains(&0x14)   // No validation
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractSharedSequencerVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractSharedSequencer,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Shared Sequencer: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement sequencer independence checks", vuln.location),
        }).collect()
    }
}
