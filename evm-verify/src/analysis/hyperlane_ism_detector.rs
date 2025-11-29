/// Hyperlane ISM (Interchain Security Module) Detector
/// Detects vulnerabilities in Hyperlane modular bridge security
/// Critical for: Hyperlane cross-chain messaging

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperlaneISMVulnerability {
    pub vulnerability_type: HyperlaneISMIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HyperlaneISMIssueType {
    ISMConfigurationExploit,       // ISM configuration vulnerability
    MultisigISMCollusion,          // Multi-sig ISM collusion
    RoutingISMManipulation,        // Routing ISM manipulation
    AggregationISMBypass,          // Aggregation ISM bypass
    ISMValidationFailure,          // ISM validation insufficient
}

pub struct HyperlaneISMDetector {
    bytecode: Vec<u8>,
}

impl HyperlaneISMDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HyperlaneISMVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_hyperlane_ism() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_configuration_issues());
        vulnerabilities.extend(self.detect_validation_gaps());

        vulnerabilities
    }

    fn detect_configuration_issues(&self) -> Vec<HyperlaneISMVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.configures_ism(i) && !self.validates_ism_config(i) {
                vulnerabilities.push(HyperlaneISMVulnerability {
                    vulnerability_type: HyperlaneISMIssueType::ISMConfigurationExploit,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Hyperlane ISM configuration without validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. ISM (Interchain Security Module) configured\n\
                        2. No validation of ISM parameters\n\
                        3. Malicious ISM configuration\n\
                        4. Cross-chain message security compromised\n\n\
                        Fix: Validate ISM configuration thoroughly",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_validation_gaps(&self) -> Vec<HyperlaneISMVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.processes_message(i) && !self.validates_ism(i) {
                vulnerabilities.push(HyperlaneISMVulnerability {
                    vulnerability_type: HyperlaneISMIssueType::ISMValidationFailure,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.80,
                    description: "Cross-chain message processing without ISM validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract processes Hyperlane message\n\
                        2. ISM validation skipped or weak\n\
                        3. Attacker sends fake cross-chain message\n\
                        4. Unauthorized action executed\n\n\
                        Fix: Always validate via ISM before processing",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_hyperlane_ism(&self) -> bool {
        let verify = [0x92, 0x63, 0xf4, 0x88]; // verify() ISM function
        self.bytecode.windows(4).any(|w| w == verify)
    }

    fn configures_ism(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len() && self.bytecode[pos] == 0x55 // SSTORE (config)
    }

    fn validates_ism_config(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x14 {
                return true;
            }
        }
        false
    }

    fn processes_message(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn validates_ism(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(40)..pos {
            if self.bytecode[i] == 0xFA { // STATICCALL to ISM
                return true;
            }
        }
        false
    }
}
