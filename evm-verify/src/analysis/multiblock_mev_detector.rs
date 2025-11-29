/// Multi-Block MEV Attack Detector
/// Detects vulnerabilities to multi-block MEV extraction
/// Critical for: PBS evolution, proposer lookahead attacks

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiBlockMEVVulnerability {
    pub vulnerability_type: MultiBlockMEVIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiBlockMEVIssueType {
    MultiBlockAuctionManipulation, // Auction spanning multiple blocks
    ProposerLookaheadAttack,       // Proposer lookahead exploitation
    MEVAcrossBlocks,               // MEV extracted over multiple blocks
    TemporalArbitrage,             // Arbitrage opportunity >1 block
    BlockSpaceHoarding,            // Hoarding block space for MEV
}

pub struct MultiBlockMEVDetector {
    bytecode: Vec<u8>,
}

impl MultiBlockMEVDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiBlockMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_multi_block_auctions());
        vulnerabilities.extend(self.detect_temporal_dependencies());

        vulnerabilities
    }

    fn detect_multi_block_auctions(&self) -> Vec<MultiBlockMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_auction_mechanism(i) && self.spans_multiple_blocks(i) {
                if !self.has_block_manipulation_protection(i) {
                    vulnerabilities.push(MultiBlockMEVVulnerability {
                        vulnerability_type: MultiBlockMEVIssueType::MultiBlockAuctionManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Multi-block auction without manipulation protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Auction spans multiple blocks\n\
                            2. Proposer can see future blocks\n\
                            3. Proposer manipulates auction across blocks\n\
                            4. Extracts MEV via lookahead\n\n\
                            Fix: Use VDF or commit-reveal spanning blocks",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_temporal_dependencies(&self) -> Vec<MultiBlockMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_time_dependency(i) && self.vulnerable_to_timing(i) {
                vulnerabilities.push(MultiBlockMEVVulnerability {
                    vulnerability_type: MultiBlockMEVIssueType::TemporalArbitrage,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Temporal dependency enabling multi-block arbitrage".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract state changes over blocks\n\
                        2. Attacker can predict state changes\n\
                        3. Sets up position in block N\n\
                        4. Profits in block N+k via arbitrage\n\n\
                        Fix: Randomize timing or add unpredictability",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn has_auction_mechanism(&self, pos: usize) -> bool {
        let bid = [0x45, 0x24, 0x8f, 0x7c]; // bid() or similar
        pos + 4 <= self.bytecode.len() && &self.bytecode[pos..pos+4] == &bid
    }

    fn spans_multiple_blocks(&self, pos: usize) -> bool {
        // Look for block number checks
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x43 { // NUMBER
                return true;
            }
        }
        false
    }

    fn has_block_manipulation_protection(&self, pos: usize) -> bool {
        // Look for commit-reveal or VDF
        for i in pos.saturating_sub(40)..pos {
            if self.bytecode[i] == 0x20 { // KECCAK256
                return true;
            }
        }
        false
    }

    fn has_time_dependency(&self, pos: usize) -> bool {
        // Look for TIMESTAMP or NUMBER
        pos + 10 < self.bytecode.len() &&
        (self.bytecode[pos] == 0x42 || self.bytecode[pos] == 0x43)
    }

    fn vulnerable_to_timing(&self, pos: usize) -> bool {
        // Look for value transfer based on time
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xF1 { // CALL
                return true;
            }
        }
        false
    }
}
