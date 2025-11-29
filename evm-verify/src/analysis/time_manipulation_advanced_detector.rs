/// Advanced Time Manipulation Detector
/// Detects sophisticated time-based exploits beyond basic timestamp
/// Critical for: Advanced timing attacks

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTimeVulnerability {
    pub vulnerability_type: AdvancedTimeIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdvancedTimeIssueType {
    BlockNumberTimestampArbitrage,   // Block number vs timestamp arbitrage
    L2TimestampLagExploit,           // L2 timestamp lag exploitation
    ScheduledTransactionFrontrun,    // Scheduled tx frontrunning
    TimeWeightedOracleManipulation,  // TWAP manipulation over epochs
    VestingScheduleEconomicAttack,   // Vesting schedule exploit
}

pub struct AdvancedTimeManipulationDetector {
    bytecode: Vec<u8>,
}

impl AdvancedTimeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AdvancedTimeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_block_timestamp_arbitrage());
        vulnerabilities.extend(self.detect_twap_manipulation());

        vulnerabilities
    }

    fn detect_block_timestamp_arbitrage(&self) -> Vec<AdvancedTimeVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.mixes_block_and_time(i) {
                vulnerabilities.push(AdvancedTimeVulnerability {
                    vulnerability_type: AdvancedTimeIssueType::BlockNumberTimestampArbitrage,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Mixing block.number and block.timestamp creates arbitrage".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract uses both block.number and timestamp\n\
                        2. Block time varies (12-15s on Ethereum)\n\
                        3. Attacker exploits timing mismatch\n\
                        4. Arbitrage via block number vs time difference\n\n\
                        Fix: Use only one time source consistently",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_twap_manipulation(&self) -> Vec<AdvancedTimeVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.calculates_twap(i) && !self.has_manipulation_protection(i) {
                vulnerabilities.push(AdvancedTimeVulnerability {
                    vulnerability_type: AdvancedTimeIssueType::TimeWeightedOracleManipulation,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "TWAP calculation without manipulation protection".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Time-weighted average price calculated\n\
                        2. Short TWAP window or insufficient samples\n\
                        3. Attacker manipulates price over time\n\
                        4. Exploits manipulated TWAP for profit\n\n\
                        Fix: Use longer TWAP windows and multiple sources",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn mixes_block_and_time(&self, pos: usize) -> bool {
        let has_number = self.bytecode[pos..pos.saturating_add(20).min(self.bytecode.len())]
            .iter()
            .any(|&b| b == 0x43); // NUMBER
        let has_timestamp = self.bytecode[pos..pos.saturating_add(20).min(self.bytecode.len())]
            .iter()
            .any(|&b| b == 0x42); // TIMESTAMP
        has_number && has_timestamp
    }

    fn calculates_twap(&self, pos: usize) -> bool {
        // DIV with timestamp involved
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x04 && // DIV
        self.bytecode[pos..pos+10].iter().any(|&b| b == 0x42) // TIMESTAMP
    }

    fn has_manipulation_protection(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }
}
