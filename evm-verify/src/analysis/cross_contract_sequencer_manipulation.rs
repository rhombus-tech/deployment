/// Cross-Contract Sequencer Manipulation Detector
///
/// Detects vulnerabilities where L2 sequencer state can be manipulated
/// to affect cross-protocol interactions.
///
/// Examples:
/// - Optimistic rollup sequencer ordering manipulation
/// - Cross-rollup sequencer coordination attacks
/// - Sequencer-dependent oracle updates
/// - MEV extraction via sequencer control
///
/// Risk: $100B+ in L2 TVL (Arbitrum, Optimism, Base, etc.)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractSequencerManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: SequencerManipulationType,
    pub affected_l2s: Vec<String>,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SequencerManipulationType {
    /// Transaction ordering dependency
    OrderingDependency,
    /// Sequencer-controlled timestamp manipulation
    TimestampManipulation,
    /// Cross-L2 sequencer coordination
    CrossL2Coordination,
    /// Sequencer-gated state updates
    SequencerGatedUpdates,
    /// Forced inclusion bypass
    ForcedInclusionBypass,
}

pub struct CrossContractSequencerManipulationAnalyzer;

impl CrossContractSequencerManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractSequencerManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_ordering_dependency(bytecode) {
            vulnerabilities.push(CrossContractSequencerManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Cross-protocol operation depends on sequencer transaction ordering".to_string(),
                location: "Order-dependent logic".to_string(),
                manipulation_type: SequencerManipulationType::OrderingDependency,
                affected_l2s: vec!["Optimistic rollups".to_string()],
                impact: "Sequencer can reorder transactions to frontrun or sandwich cross-protocol operations".to_string(),
            });
        }

        if self.has_sequencer_timestamp_dependency(bytecode) {
            vulnerabilities.push(CrossContractSequencerManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Sequencer-controlled timestamp affects cross-protocol state".to_string(),
                location: "Timestamp usage".to_string(),
                manipulation_type: SequencerManipulationType::TimestampManipulation,
                affected_l2s: vec!["All L2s".to_string()],
                impact: "Sequencer timestamp manipulation can affect time-sensitive cross-protocol logic".to_string(),
            });
        }

        if self.has_cross_l2_sequencer_dependency(bytecode) {
            vulnerabilities.push(CrossContractSequencerManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Cross-L2 operation assumes independent sequencers".to_string(),
                location: "Cross-L2 messaging".to_string(),
                manipulation_type: SequencerManipulationType::CrossL2Coordination,
                affected_l2s: vec!["Multiple L2s".to_string()],
                impact: "Coordinated sequencers can manipulate cross-L2 state atomically".to_string(),
            });
        }

        if self.has_sequencer_gated_updates(bytecode) {
            vulnerabilities.push(CrossContractSequencerManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Critical updates gated by sequencer inclusion".to_string(),
                location: "State update logic".to_string(),
                manipulation_type: SequencerManipulationType::SequencerGatedUpdates,
                affected_l2s: vec!["Optimistic rollups".to_string()],
                impact: "Sequencer can delay or prevent critical cross-protocol updates".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_ordering_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for: state reads followed by writes based on external calls
        // This creates ordering dependency
        bytecode.windows(50).any(|window| {
            window.contains(&0x54) && // SLOAD (read state)
            window.contains(&0xfa) && // STATICCALL (read external)
            window.contains(&0x55) && // SSTORE (write state)
            window.contains(&0x10)    // LT (comparison - order matters)
        })
    }

    fn has_sequencer_timestamp_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for: TIMESTAMP usage in cross-protocol logic
        bytecode.contains(&0x42) && // TIMESTAMP
        bytecode.windows(40).any(|window| {
            window.contains(&0x42) && // TIMESTAMP
            (window.contains(&0xf1) || window.contains(&0xfa)) && // External call
            window.contains(&0x55)    // State update based on timestamp
        })
    }

    fn has_cross_l2_sequencer_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for: cross-chain messaging without sequencer coordination checks
        // Common L2 bridge function signatures
        let bridge_sigs = [
            &[0x83, 0x82, 0x59, 0x19][..], // sendMessage()
            &[0x3d, 0xbb, 0x3b, 0xfa][..], // relayMessage()
        ];

        bridge_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && !bytecode.windows(30).any(|window| {
            // No sequencer coordination check
            window.contains(&0x41) // COINBASE (sequencer address)
        })
    }

    fn has_sequencer_gated_updates(&self, bytecode: &[u8]) -> bool {
        // Look for: critical updates that require external confirmation
        bytecode.windows(50).any(|window| {
            window.contains(&0x55) && // SSTORE (critical update)
            window.contains(&0xfa) && // External call (confirmation needed)
            !window.contains(&0x42)   // No timestamp fallback
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractSequencerManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractSequencerManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Sequencer Manipulation: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Minimize sequencer dependencies and use timestamp/ordering protections", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering_dependency() {
        let analyzer = CrossContractSequencerManipulationAnalyzer::new();
        
        let bytecode = vec![
            0x54, // SLOAD
            0xfa, // STATICCALL
            0x10, // LT
            0x55, // SSTORE
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
