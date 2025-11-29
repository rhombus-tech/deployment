/// Preconfirmation Mechanism Exploit Detector
/// Detects vulnerabilities in L2 preconfirmation systems
/// Critical for: L2s with instant finality via preconfs

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconfirmationVulnerability {
    pub vulnerability_type: PreconfirmationIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreconfirmationIssueType {
    PreconfVsFinalDivergence,      // Preconf state ≠ final state
    PreconfRevertAttack,           // Preconfirm then revert
    SequencerPreconfFraud,         // Sequencer false preconfirmation
    CrossPreconfArbitrage,         // Arbitrage across preconf systems
    CollateralSlashingBypass,      // Bypass preconf collateral slashing
}

pub struct PreconfirmationDetector {
    bytecode: Vec<u8>,
}

impl PreconfirmationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PreconfirmationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_preconfirmations() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_divergence_risks());
        vulnerabilities.extend(self.detect_revert_attacks());

        vulnerabilities
    }

    fn detect_divergence_risks(&self) -> Vec<PreconfirmationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.relies_on_preconf(i) && !self.validates_finality(i) {
                vulnerabilities.push(PreconfirmationVulnerability {
                    vulnerability_type: PreconfirmationIssueType::PreconfVsFinalDivergence,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Reliance on preconfirmation without final state validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract acts on preconfirmed transaction\n\
                        2. No verification against final settled state\n\
                        3. Final state diverges from preconf\n\
                        4. Business logic based on wrong state\n\n\
                        Fix: Verify preconf matches final settlement",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_revert_attacks(&self) -> Vec<PreconfirmationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.accepts_preconf(i) && !self.has_slashing_enforcement(i) {
                vulnerabilities.push(PreconfirmationVulnerability {
                    vulnerability_type: PreconfirmationIssueType::PreconfRevertAttack,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Preconfirmation acceptance without slashing guarantee".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Sequencer provides preconfirmation\n\
                        2. Contract accepts and acts on it\n\
                        3. Sequencer reverts transaction\n\
                        4. No collateral slashing enforced\n\n\
                        Fix: Ensure slashing is automatic and enforced",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_preconfirmations(&self) -> bool {
        // Heuristic: Look for preconf-related signatures
        let preconf_sig = [0x4a, 0x7b, 0x29, 0x87]; // preconfirm()
        self.bytecode.windows(4).any(|w| w == preconf_sig)
    }

    fn relies_on_preconf(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn validates_finality(&self, pos: usize) -> bool {
        // Look for finality check
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x14 { // EQ (state check)
                return true;
            }
        }
        false
    }

    fn accepts_preconf(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn has_slashing_enforcement(&self, pos: usize) -> bool {
        // Look for slashing validation
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x54 { // SLOAD (slashing state)
                return true;
            }
        }
        false
    }
}
