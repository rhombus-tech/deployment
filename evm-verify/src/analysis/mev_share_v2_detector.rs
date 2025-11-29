/// MEV-Share V2 Order Flow Auction Detector
/// Detects vulnerabilities in MEV-Share v2 OFA mechanisms
/// Critical for: Flashbots MEV-Share v2

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MEVShareV2Vulnerability {
    pub vulnerability_type: MEVShareV2IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MEVShareV2IssueType {
    OFAManipulation,               // Order flow auction manipulation
    SearcherCollusionAuction,      // Searcher collusion in auctions
    BuilderPreferenceGaming,       // Builder preference exploitation
    RefundCalculationV2Exploit,    // MEV refund v2 calculation exploit
    PrivateOrderflowLeakage,       // Private orderflow information leakage
}

pub struct MEVShareV2Detector {
    bytecode: Vec<u8>,
}

impl MEVShareV2Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MEVShareV2Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_mev_share_v2() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_ofa_issues());
        vulnerabilities.extend(self.detect_leakage_risks());

        vulnerabilities
    }

    fn detect_ofa_issues(&self) -> Vec<MEVShareV2Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.participates_in_ofa(i) && !self.validates_ofa_rules(i) {
                vulnerabilities.push(MEVShareV2Vulnerability {
                    vulnerability_type: MEVShareV2IssueType::OFAManipulation,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "OFA participation without proper rule validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract participates in Order Flow Auction\n\
                        2. No validation of auction rules/parameters\n\
                        3. Attacker manipulates auction mechanism\n\
                        4. Unfair MEV distribution or user loss\n\n\
                        Fix: Validate OFA parameters thoroughly",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_leakage_risks(&self) -> Vec<MEVShareV2Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.exposes_orderflow_data(i) {
                vulnerabilities.push(MEVShareV2Vulnerability {
                    vulnerability_type: MEVShareV2IssueType::PrivateOrderflowLeakage,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Private orderflow data exposed prematurely".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract handles private orderflow\n\
                        2. Orderflow data leaked before execution\n\
                        3. Searchers see private intent early\n\
                        4. MEV extraction before user execution\n\n\
                        Fix: Maintain orderflow privacy until execution",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_mev_share_v2(&self) -> bool {
        let ofa_sig = [0x9f, 0x4e, 0xb2, 0x77]; // submitToOFA() or similar
        self.bytecode.windows(4).any(|w| w == ofa_sig)
    }

    fn participates_in_ofa(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn validates_ofa_rules(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x14 || self.bytecode[i] == 0x10 {
                return true;
            }
        }
        false
    }

    fn exposes_orderflow_data(&self, pos: usize) -> bool {
        // LOG opcodes that may leak data
        pos < self.bytecode.len() &&
        (self.bytecode[pos] >= 0xA0 && self.bytecode[pos] <= 0xA4)
    }
}
