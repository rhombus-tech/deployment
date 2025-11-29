/// L2 Timestamp Dependency Detector
/// Detects vulnerabilities where contracts rely on block.timestamp
/// on L2s where sequencers control timestamps (Arbitrum, Optimism, Base, etc.)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TimestampVulnerability {
    pub vulnerability_type: L2TimestampIssue,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2TimestampIssue {
    TimestampForRandomness,        // Using timestamp for randomness on L2
    CriticalTimingLogic,           // Time-critical operations on L2
    AuctionTimestampDependency,    // Auction timing controllable by sequencer
    VestingScheduleManipulation,   // Vesting unlocks controllable
}

pub struct L2TimestampDependencyDetector {
    bytecode: Vec<u8>,
}

impl L2TimestampDependencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<L2TimestampVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_timestamp_randomness());
        vulnerabilities.extend(self.detect_critical_timing());

        vulnerabilities
    }

    fn detect_timestamp_randomness(&self) -> Vec<L2TimestampVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[pc] == 0x42 { // TIMESTAMP
                // Check if used in KECCAK256 (randomness generation)
                if self.has_keccak_after(pc, 15) {
                    vulnerabilities.push(L2TimestampVulnerability {
                        vulnerability_type: L2TimestampIssue::TimestampForRandomness,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Contract uses block.timestamp at PC {} for randomness. \
                            On L2s, sequencer controls timestamps and can manipulate this.",
                            pc
                        ),
                        exploit_scenario:
                            "L2 Sequencer Timestamp Manipulation:\n\
                             1. Contract generates random number using block.timestamp\n\
                             2. On Arbitrum/Optimism, sequencer controls timestamp\n\
                             3. Sequencer delays block to get favorable timestamp\n\
                             4. Randomness becomes predictable/controllable\n\
                             5. Sequencer or colluding party wins lottery/raffle\n\n\
                             Fix: Use Chainlink VRF or commit-reveal scheme".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn detect_critical_timing(&self) -> Vec<L2TimestampVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[pc] == 0x42 { // TIMESTAMP
                // Check if used in time-critical comparisons
                if self.has_critical_comparison_after(pc, 5) {
                    let has_buffer = self.has_time_buffer_nearby(pc, 20);
                    
                    if !has_buffer {
                        vulnerabilities.push(L2TimestampVulnerability {
                            vulnerability_type: L2TimestampIssue::CriticalTimingLogic,
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: format!(
                                "Time-critical logic at PC {} without buffer. \
                                L2 sequencer can manipulate precise timing.",
                                pc
                            ),
                            exploit_scenario:
                                "L2 Timing Manipulation:\n\
                                 1. Auction ends exactly at block.timestamp == deadline\n\
                                 2. Sequencer can delay block by seconds\n\
                                 3. Legitimate bids excluded by timestamp manipulation\n\
                                 4. Sequencer's bid wins unfairly\n\n\
                                 Fix: Add grace period or use block.number on L2".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn has_keccak_after(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        self.bytecode[start..end].contains(&0x20) // KECCAK256
    }

    fn has_critical_comparison_after(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for EQ, LT, GT (exact timing checks)
        self.bytecode[start..end].iter()
            .any(|&op| matches!(op, 0x10 | 0x11 | 0x14))
    }

    fn has_time_buffer_nearby(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        let end = (pc + distance).min(self.bytecode.len());
        
        // Look for ADD with large constant (grace period)
        for i in start..end.saturating_sub(3) {
            if self.bytecode[i] == 0x01 { // ADD
                // Check if adding a significant time buffer (> 1 hour = 3600s)
                if self.has_large_constant_before(i, 5) {
                    return true;
                }
            }
        }
        false
    }

    fn has_large_constant_before(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        
        // Look for PUSH2+ (constants > 255)
        for i in start..pc {
            if matches!(self.bytecode.get(i), Some(&op) if op >= 0x61 && op <= 0x7f) {
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
    fn test_timestamp_randomness() {
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x20, // KECCAK256 (randomness)
        ];
        
        let detector = L2TimestampDependencyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
