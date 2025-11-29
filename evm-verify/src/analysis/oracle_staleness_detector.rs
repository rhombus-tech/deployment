/// Oracle Staleness Detector
/// Detects when price oracles return stale data without proper validation
/// Critical for: Chainlink, Uniswap v3 TWAP, any price feed

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleStalenessVulnerability {
    pub vulnerability_type: OracleStalenessIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OracleStalenessIssueType {
    NoUpdatedAtCheck,              // Chainlink updatedAt not checked
    NoHeartbeatValidation,         // Heartbeat exceeded not detected
    StaleTWAPObservation,          // Uniswap TWAP observation too old
    MultipleOracleDisagreement,    // Oracles disagree but no check
    NoRoundIdCheck,                // Round ID not validated
}

pub struct OracleStalenessDetector {
    bytecode: Vec<u8>,
    oracle_selectors: HashSet<[u8; 4]>,
}

impl OracleStalenessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut oracle_selectors = HashSet::new();
        oracle_selectors.insert([0xfe, 0xaf, 0x96, 0x8c]); // latestRoundData()
        oracle_selectors.insert([0x50, 0xd2, 0x5b, 0xcd]); // latestAnswer()
        oracle_selectors.insert([0x88, 0x38, 0xf3, 0x4c]); // observe() Uniswap v3
        
        Self { bytecode, oracle_selectors }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OracleStalenessVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_oracles() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_chainlink_staleness());
        vulnerabilities.extend(self.detect_twap_staleness());

        vulnerabilities
    }

    fn detect_chainlink_staleness(&self) -> Vec<OracleStalenessVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_chainlink_call(i) {
                // Check for updatedAt validation
                if !self.has_timestamp_check(i) {
                    vulnerabilities.push(OracleStalenessVulnerability {
                        vulnerability_type: OracleStalenessIssueType::NoUpdatedAtCheck,
                        severity: SecuritySeverity::High,
                        confidence: 0.85,
                        description: "Chainlink price feed updatedAt timestamp not validated".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Oracle stops updating (circuit breaker)\n\
                            2. Contract uses stale price from hours/days ago\n\
                            3. Attacker exploits stale price for arbitrage\n\
                            4. Protocol incurs losses from outdated data\n\n\
                            Fix: require(block.timestamp - updatedAt < HEARTBEAT)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_twap_staleness(&self) -> Vec<OracleStalenessVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_uniswap_observe(i) {
                // Check for observation age validation
                if !self.has_observation_age_check(i) {
                    vulnerabilities.push(OracleStalenessVulnerability {
                        vulnerability_type: OracleStalenessIssueType::StaleTWAPObservation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: "Uniswap v3 TWAP observation age not validated".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Pool has no recent swaps\n\
                            2. Last observation is hours old\n\
                            3. TWAP reflects stale price\n\
                            4. Attacker manipulates with large swap\n\n\
                            Fix: Ensure recent observations available",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn uses_oracles(&self) -> bool {
        for selector in &self.oracle_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        false
    }

    fn is_chainlink_call(&self, pos: usize) -> bool {
        if pos + 4 > self.bytecode.len() {
            return false;
        }
        let chainlink = [0xfe, 0xaf, 0x96, 0x8c];
        &self.bytecode[pos..pos+4] == &chainlink
    }

    fn is_uniswap_observe(&self, pos: usize) -> bool {
        if pos + 4 > self.bytecode.len() {
            return false;
        }
        let observe = [0x88, 0x38, 0xf3, 0x4c];
        &self.bytecode[pos..pos+4] == &observe
    }

    fn has_timestamp_check(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn has_observation_age_check(&self, pos: usize) -> bool {
        // Similar to timestamp check
        self.has_timestamp_check(pos)
    }
}
