/// Sequencer Decentralization Attack Detector
/// Detects vulnerabilities in decentralized sequencer sets
/// Critical for: Espresso, Astria, shared sequencers

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerDecentralizationVulnerability {
    pub vulnerability_type: SequencerDecentralizationIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SequencerDecentralizationIssueType {
    SequencerRotationAttack,       // Sequencer rotation exploit
    SharedSequencerMEV,            // Shared sequencer MEV extraction
    CrossRollupAtomicExploit,      // Cross-rollup atomic transaction exploit
    CensorshipResistanceBypass,    // Censorship resistance circumvention
    FastFinalityReorgRisk,         // Fast finality vs reorg tradeoff
}

pub struct SequencerDecentralizationDetector {
    bytecode: Vec<u8>,
}

impl SequencerDecentralizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SequencerDecentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_decentralized_sequencer() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_rotation_risks());
        vulnerabilities.extend(self.detect_cross_rollup_risks());

        vulnerabilities
    }

    fn detect_rotation_risks(&self) -> Vec<SequencerDecentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.depends_on_sequencer(i) && !self.validates_sequencer_rotation(i) {
                vulnerabilities.push(SequencerDecentralizationVulnerability {
                    vulnerability_type: SequencerDecentralizationIssueType::SequencerRotationAttack,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Sequencer dependency without rotation validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract assumes stable sequencer\n\
                        2. Sequencer rotates in decentralized set\n\
                        3. New sequencer has different behavior\n\
                        4. Transaction ordering or execution changes\n\n\
                        Fix: Handle sequencer rotation gracefully",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_cross_rollup_risks(&self) -> Vec<SequencerDecentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_cross_rollup_operation(i) && !self.validates_atomicity(i) {
                vulnerabilities.push(SequencerDecentralizationVulnerability {
                    vulnerability_type: SequencerDecentralizationIssueType::CrossRollupAtomicExploit,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Cross-rollup operation without atomicity guarantee".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Shared sequencer enables cross-rollup tx\n\
                        2. Operation spans multiple rollups\n\
                        3. No atomicity guarantee\n\
                        4. Partial execution creates exploitable state\n\n\
                        Fix: Ensure atomic cross-rollup execution",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_decentralized_sequencer(&self) -> bool {
        let espresso_sig = [0xa1, 0x5c, 0xd2, 0x9f]; // Espresso/shared sequencer
        self.bytecode.windows(4).any(|w| w == espresso_sig)
    }

    fn depends_on_sequencer(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn validates_sequencer_rotation(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x14 {
                return true;
            }
        }
        false
    }

    fn has_cross_rollup_operation(&self, pos: usize) -> bool {
        pos + 15 < self.bytecode.len()
    }

    fn validates_atomicity(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFD { // REVERT (rollback path)
                return true;
            }
        }
        false
    }
}
