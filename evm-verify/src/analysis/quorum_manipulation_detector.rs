// Quorum Manipulation Detector
// Detects strategic abstention and quorum gaming attacks

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumManipulationVulnerability {
    pub location: usize,
    pub vulnerability_type: QuorumManipulationType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuorumManipulationType {
    StrategicAbstention,             // Abstain to prevent quorum
    LastMinuteVoting,                // Vote manipulation at deadline
    VoteSplitting,                   // Split votes across proposals
    QuorumThresholdGaming,           // Manipulate quorum calculation
    ParticipationRateManipulation,   // Game overall participation metrics
    VotingPowerConcentration,        // Concentrated power defeats quorum
}

pub struct QuorumManipulationDetector {
    bytecode: Vec<u8>,
}

impl QuorumManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<QuorumManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_strategic_abstention() {
            vulnerabilities.push(QuorumManipulationVulnerability {
                location: loc,
                vulnerability_type: QuorumManipulationType::StrategicAbstention,
                severity: "High".to_string(),
                description: "Quorum calculated based on voting participation. Large token holders \
                             can abstain strategically to prevent proposals from reaching quorum.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_last_minute_voting() {
            vulnerabilities.push(QuorumManipulationVulnerability {
                location: loc,
                vulnerability_type: QuorumManipulationType::LastMinuteVoting,
                severity: "Medium".to_string(),
                description: "No restrictions on voting near proposal deadline. Last-minute votes \
                             can manipulate outcome or quorum status unexpectedly.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_vote_splitting() {
            vulnerabilities.push(QuorumManipulationVulnerability {
                location: loc,
                vulnerability_type: QuorumManipulationType::VoteSplitting,
                severity: "Medium".to_string(),
                description: "Voting power can be split across multiple proposals. Attacker dilutes \
                             participation to prevent quorum on legitimate proposals.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_quorum_threshold_gaming() {
            vulnerabilities.push(QuorumManipulationVulnerability {
                location: loc,
                vulnerability_type: QuorumManipulationType::QuorumThresholdGaming,
                severity: "High".to_string(),
                description: "Quorum threshold manipulable through token supply changes. Minting or \
                             burning tokens can alter quorum requirements mid-proposal.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_participation_rate_manipulation() {
            vulnerabilities.push(QuorumManipulationVulnerability {
                location: loc,
                vulnerability_type: QuorumManipulationType::ParticipationRateManipulation,
                severity: "High".to_string(),
                description: "Participation rate calculation vulnerable to manipulation. Historical \
                             averages can be skewed through spam voting or abstention.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_voting_power_concentration() {
            vulnerabilities.push(QuorumManipulationVulnerability {
                location: loc,
                vulnerability_type: QuorumManipulationType::VotingPowerConcentration,
                severity: "Critical".to_string(),
                description: "No limits on voting power concentration. Single entity can control \
                             quorum achievement through large token holdings.".to_string(),
                confidence: 0.91,
            });
        }

        vulnerabilities
    }

    fn detect_strategic_abstention(&self) -> Option<usize> {
        // Pattern: Quorum based on votes cast rather than total eligible
        // DIV operation using participated votes as denominator
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x04 {  // DIV (quorum calculation)
                let mut uses_participated = false;
                let mut uses_total_supply = false;
                
                // Check if numerator is votes cast
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (votes for + against)
                        uses_participated = true;
                    }
                }
                
                // Check if denominator is total token supply (should be)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        // Total supply typically at specific slot
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x04 {  // DIV (using supply)
                                uses_total_supply = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if using participated votes without total supply context
                if uses_participated && !uses_total_supply {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_last_minute_voting(&self) -> Option<usize> {
        // Pattern: Vote acceptance without deadline buffer
        // TIMESTAMP check allows votes up to exact deadline
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (record vote)
                let mut has_deadline_check = false;
                let mut has_buffer = false;
                
                // Check for deadline verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (before deadline)
                                has_deadline_check = true;
                                
                                // Check for buffer (subtraction from deadline)
                                for m in (k.saturating_sub(10))..k {
                                    if self.bytecode[m] == 0x03 {  // SUB (buffer time)
                                        has_buffer = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if has_deadline_check && !has_buffer {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_vote_splitting(&self) -> Option<usize> {
        // Pattern: No limit on concurrent voting across proposals
        // Can vote on multiple proposals simultaneously
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (cast vote)
                let mut is_vote = false;
                let mut checks_other_votes = false;
                
                // Check if vote recording
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_vote = true;
                    }
                }
                
                // Check for existing active votes from same address
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (active vote count)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (under limit)
                                checks_other_votes = true;
                            }
                        }
                    }
                }
                
                if is_vote && !checks_other_votes {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_quorum_threshold_gaming(&self) -> Option<usize> {
        // Pattern: Quorum uses current supply without snapshot
        // Total supply can change after proposal creation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (total supply for quorum)
                let mut calculates_quorum = false;
                let mut uses_snapshot = false;
                
                // Check if used in quorum calculation
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV
                        calculates_quorum = true;
                    }
                }
                
                // Check for snapshot mechanism (proposal ID used to get supply)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (proposal ID)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x20 {  // SHA3 (snapshot key)
                                uses_snapshot = true;
                            }
                        }
                    }
                }
                
                if calculates_quorum && !uses_snapshot {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_participation_rate_manipulation(&self) -> Option<usize> {
        // Pattern: Historical participation average without outlier filtering
        // Average calculated including manipulated data points
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x04 {  // DIV (calculate average)
                let mut is_avg_calc = false;
                let mut filters_outliers = false;
                
                // Check if averaging participation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (sum for average)
                        is_avg_calc = true;
                    }
                }
                
                // Check for outlier filtering (min/max bounds)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x10 && is_avg_calc {  // LT (filter low)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x11 {  // GT (filter high)
                                filters_outliers = true;
                            }
                        }
                    }
                }
                
                if is_avg_calc && !filters_outliers {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_voting_power_concentration(&self) -> Option<usize> {
        // Pattern: No maximum voting power cap per address
        // Single address can hold unlimited percentage of supply
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (voting power/balance)
                let mut used_in_vote = false;
                let mut has_power_cap = false;
                
                // Check if used for voting
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (record vote with this power)
                        used_in_vote = true;
                    }
                }
                
                // Check for maximum power cap (percentage of supply)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 {  // LT (power < max)
                        for k in (j.saturating_sub(10))..j {
                            if self.bytecode[k] == 0x04 {  // DIV (calculate max %)
                                has_power_cap = true;
                            }
                        }
                    }
                }
                
                if used_in_vote && !has_power_cap {
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
    fn test_strategic_abstention() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (votes cast)
            0x60, 0x64, // PUSH1 100
            0x04, // DIV (quorum without total supply check)
        ];
        
        let detector = QuorumManipulationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, QuorumManipulationType::StrategicAbstention)));
    }

    #[test]
    fn test_voting_power_concentration() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (voting power - no cap)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (record vote)
        ];
        
        let detector = QuorumManipulationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, QuorumManipulationType::VotingPowerConcentration)));
    }
}
