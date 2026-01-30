// Proposal Spam DOS Detector
// Detects governance queue flooding and proposal spam attacks

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalSpamDosVulnerability {
    pub location: usize,
    pub vulnerability_type: ProposalSpamType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalSpamType {
    GovernanceQueueFlooding,         // Spam proposals to fill queue
    MinimumProposalThresholdBypass,  // Bypass minimum token requirement
    ProposalCancellationGriefing,    // Cancel proposals to grief system
    VotingPeriodExhaustion,          // Exhaust voting periods through spam
    QuorumManipulationSpam,          // Spam to manipulate quorum calculations
    ProposalExecutionDOS,            // Prevent execution through queue overflow
}

pub struct ProposalSpamDosDetector {
    bytecode: Vec<u8>,
}

impl ProposalSpamDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProposalSpamDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_governance_queue_flooding() {
            vulnerabilities.push(ProposalSpamDosVulnerability {
                location: loc,
                vulnerability_type: ProposalSpamType::GovernanceQueueFlooding,
                severity: "Critical".to_string(),
                description: "Proposal submission lacks rate limiting or queue size cap. Attacker \
                             can flood governance queue preventing legitimate proposals.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_minimum_proposal_threshold_bypass() {
            vulnerabilities.push(ProposalSpamDosVulnerability {
                location: loc,
                vulnerability_type: ProposalSpamType::MinimumProposalThresholdBypass,
                severity: "High".to_string(),
                description: "Minimum token threshold for proposals bypassable or too low. \
                             Allows low-cost spam attacks on governance.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_proposal_cancellation_griefing() {
            vulnerabilities.push(ProposalSpamDosVulnerability {
                location: loc,
                vulnerability_type: ProposalSpamType::ProposalCancellationGriefing,
                severity: "High".to_string(),
                description: "Proposal cancellation lacks restrictions. Anyone can cancel proposals \
                             through griefing attacks disrupting governance.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_voting_period_exhaustion() {
            vulnerabilities.push(ProposalSpamDosVulnerability {
                location: loc,
                vulnerability_type: ProposalSpamType::VotingPeriodExhaustion,
                severity: "Medium".to_string(),
                description: "No limit on concurrent active proposals. Spam proposals exhaust \
                             voter attention and participation reducing governance effectiveness.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_quorum_manipulation_spam() {
            vulnerabilities.push(ProposalSpamDosVulnerability {
                location: loc,
                vulnerability_type: ProposalSpamType::QuorumManipulationSpam,
                severity: "High".to_string(),
                description: "Quorum calculated across all proposals. Spam proposals dilute \
                             participation rate making legitimate proposals fail quorum.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_proposal_execution_dos() {
            vulnerabilities.push(ProposalSpamDosVulnerability {
                location: loc,
                vulnerability_type: ProposalSpamType::ProposalExecutionDOS,
                severity: "Critical".to_string(),
                description: "Execution queue unbounded. Spam proposals prevent legitimate ones \
                             from executing through queue overflow.".to_string(),
                confidence: 0.89,
            });
        }

        vulnerabilities
    }

    fn detect_governance_queue_flooding(&self) -> Option<usize> {
        // Pattern: Proposal creation without rate limiting
        // SSTORE new proposal without checking recent proposal count from caller
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (create proposal)
                let mut is_proposal = false;
                let mut has_rate_limit = false;
                
                // Check if this is proposal creation (increments proposal counter)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increment proposal ID)
                        is_proposal = true;
                    }
                }
                
                // Check for rate limiting (SLOAD recent proposal timestamp)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x54 {  // SLOAD (last proposal time)
                                for m in k+1..(k+8).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x42 {  // TIMESTAMP
                                        for n in m+1..(m+5).min(self.bytecode.len()) {
                                            if self.bytecode[n] == 0x03 || self.bytecode[n] == 0x10 {  // SUB/LT (time check)
                                                has_rate_limit = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_proposal && !has_rate_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_minimum_proposal_threshold_bypass(&self) -> Option<usize> {
        // Pattern: Proposal threshold check with low or bypassable value
        // Token balance check with inadequate minimum
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (token balance)
                let mut has_threshold = false;
                let mut threshold_adequate = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Threshold comparison
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_threshold = true;
                        
                        // Check threshold value (should be PUSH2+ for adequate threshold)
                        for k in (j.saturating_sub(10))..j {
                            if self.bytecode[k] == 0x61 || self.bytecode[k] == 0x62 {  // PUSH2/PUSH3
                                threshold_adequate = true;
                            }
                        }
                    }
                }
                
                if has_threshold && !threshold_adequate {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_proposal_cancellation_griefing(&self) -> Option<usize> {
        // Pattern: Cancel function without proper authorization
        // Proposal state change without proposer check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (cancel proposal)
                let mut is_cancellation = false;
                let mut checks_proposer = false;
                
                // Look for state transition indicating cancellation
                for j in (i.saturating_sub(20))..i {
                    // Cancellation typically sets state to specific value
                    if self.bytecode[j] == 0x60 {  // PUSH1 (cancelled state)
                        is_cancellation = true;
                    }
                }
                
                // Check for proposer authorization
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x54 {  // SLOAD (proposer)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x14 {  // EQ (check if caller is proposer)
                                        checks_proposer = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_cancellation && !checks_proposer {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_voting_period_exhaustion(&self) -> Option<usize> {
        // Pattern: No limit on concurrent active proposals
        // Proposal creation without checking active count
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (new proposal)
                let mut is_proposal_create = false;
                let mut checks_active_limit = false;
                
                // Check if proposal creation
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increment counter)
                        is_proposal_create = true;
                    }
                }
                
                // Check for active proposal count limit
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (active count)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (under limit)
                                checks_active_limit = true;
                            }
                        }
                    }
                }
                
                if is_proposal_create && !checks_active_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_quorum_manipulation_spam(&self) -> Option<usize> {
        // Pattern: Quorum calculation includes all proposals
        // Division without filtering by proposal quality/age
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x04 {  // DIV (calculate quorum percentage)
                let mut is_quorum_calc = false;
                let mut filters_proposals = false;
                
                // Check if quorum calculation (votes / total)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (vote count)
                        is_quorum_calc = true;
                    }
                }
                
                // Check for proposal filtering (age, minimum votes, etc.)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP (age filter)
                        filters_proposals = true;
                    }
                    if self.bytecode[j] == 0x10 {  // LT (minimum threshold)
                        filters_proposals = true;
                    }
                }
                
                if is_quorum_calc && !filters_proposals {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_proposal_execution_dos(&self) -> Option<usize> {
        // Pattern: Execution queue without size limit
        // Proposals queued for execution without bound
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (queue proposal)
                let mut is_execution_queue = false;
                let mut has_queue_limit = false;
                
                // Check if execution queue (proposal marked as executable)
                for j in (i.saturating_sub(20))..i {
                    // State transition to "queued" or "succeeded"
                    if self.bytecode[j] == 0x60 {  // PUSH1 (queued state)
                        is_execution_queue = true;
                    }
                }
                
                // Check for queue size limit
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (queue size)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (under max)
                                has_queue_limit = true;
                            }
                        }
                    }
                }
                
                if is_execution_queue && !has_queue_limit {
                    return Some(i);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_queue_flooding() {
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1
            0x01, // ADD (increment proposal count)
            0x55, // SSTORE (create proposal without rate limit)
        ];
        
        let detector = ProposalSpamDOSDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ProposalSpamType::GovernanceQueueFlooding)));
    }

    #[test]
    fn test_minimum_proposal_threshold_bypass() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (balance)
            0x60, 0x0A, // PUSH1 10 (very low threshold)
            0x10, // LT (check threshold)
        ];
        
        let detector = ProposalSpamDOSDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ProposalSpamType::MinimumProposalThresholdBypass)));
    }
}
