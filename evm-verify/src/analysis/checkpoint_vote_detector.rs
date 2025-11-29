/// Checkpoint/Snapshot Vote Manipulation Detector
/// Detects vulnerabilities in governance snapshot/checkpoint systems
/// where voting power can be manipulated via flash loans or timing attacks
///
/// Famous: Compound-style governance exploits

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointVoteVulnerability {
    pub vulnerability_type: CheckpointIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckpointIssueType {
    FlashLoanVotingPower,          // Can borrow voting power via flash loan
    TimestampSnapshotManipulation, // Snapshot timing is manipulable
    CheckpointBypass,              // Can bypass checkpoint system
    DoubleVoting,                  // Can vote multiple times via delegation
    SnapshotDelay,                 // Insufficient delay between snapshot and vote
}

pub struct CheckpointVoteDetector {
    bytecode: Vec<u8>,
}

impl CheckpointVoteDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CheckpointVoteVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_governance_with_snapshots() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_flash_loan_voting());
        vulnerabilities.extend(self.detect_snapshot_timing_issues());

        vulnerabilities
    }

    fn is_governance_with_snapshots(&self) -> bool {
        // Look for: getPriorVotes, snapshot, checkpoint functions
        let governance_sigs = [
            [0x78, 0x2d, 0x6f, 0xe1], // getPriorVotes
            [0x95, 0xd8, 0x9b, 0x41], // snapshot (OpenZeppelin)
        ];
        
        governance_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == sig)
        })
    }

    fn detect_flash_loan_voting(&self) -> Vec<CheckpointVoteVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if voting power is checked at current block vs historical
        let has_prior_votes = self.has_get_prior_votes();
        
        if !has_prior_votes {
            vulnerabilities.push(CheckpointVoteVulnerability {
                vulnerability_type: CheckpointIssueType::FlashLoanVotingPower,
                severity: SecuritySeverity::Critical,
                confidence: 0.80,
                description:
                    "Governance doesn't use historical voting power (getPriorVotes). \
                    Vulnerable to flash loan governance attacks.".to_string(),
                exploit_scenario:
                    "Flash Loan Governance Attack:\n\
                     1. Attacker flash borrows 10M governance tokens\n\
                     2. Proposal checks current balance, not historical\n\
                     3. Attacker proposes malicious proposal with borrowed tokens\n\
                     4. Repays flash loan same block\n\
                     5. Malicious proposal passed with zero capital\n\n\
                     Fix: Use getPriorVotes(account, proposalBlock - 1)".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn detect_snapshot_timing_issues(&self) -> Vec<CheckpointVoteVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(snapshot_pc) = self.find_snapshot_function() {
            // Check if there's a delay between snapshot and vote
            let has_delay = self.has_timestamp_delay_check(snapshot_pc, 100);
            
            if !has_delay {
                vulnerabilities.push(CheckpointVoteVulnerability {
                    vulnerability_type: CheckpointIssueType::SnapshotDelay,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description:
                        "Snapshot taken without sufficient delay. Users may not have time \
                        to delegate or acquire tokens before snapshot.".to_string(),
                    exploit_scenario:
                        "Snapshot Timing Attack:\n\
                         1. Proposal created with immediate snapshot\n\
                         2. Voters have no time to delegate or buy tokens\n\
                         3. Attacker with current large position controls vote\n\
                         4. Community cannot react\n\n\
                         Fix: Enforce minimum delay (e.g., 1 block) between proposal and snapshot".to_string(),
                    location: snapshot_pc,
                });
            }
        }

        vulnerabilities
    }

    fn has_get_prior_votes(&self) -> bool {
        let selector = [0x78, 0x2d, 0x6f, 0xe1]; // getPriorVotes
        self.bytecode.windows(4).any(|w| w == selector)
    }

    fn find_snapshot_function(&self) -> Option<usize> {
        let selector = [0x95, 0xd8, 0x9b, 0x41]; // snapshot
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn has_timestamp_delay_check(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for TIMESTAMP followed by comparison
        for i in start..end.saturating_sub(2) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               matches!(self.bytecode.get(i + 1), Some(&0x10) | Some(&0x11)) { // LT or GT
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_prior_votes() {
        let bytecode = vec![
            0x95, 0xd8, 0x9b, 0x41, // snapshot() selector
            // No getPriorVotes = vulnerable
        ];
        
        let detector = CheckpointVoteDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
