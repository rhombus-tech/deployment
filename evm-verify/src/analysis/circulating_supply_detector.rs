/// Circulating Supply Manipulation Detector
/// Detects vulnerabilities in token supply oracle integrations
/// Critical for: Market cap oracles, supply-dependent mechanisms

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CirculatingSupplyVulnerability {
    pub vulnerability_type: CirculatingSupplyIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CirculatingSupplyIssueType {
    BurnAddressNotExcluded,        // Burn address included in supply
    LockedTokensNotCounted,        // Locked tokens counted as circulating
    BridgeBalanceManipulation,     // Bridge balance affects supply
    RebasingSupplyConfusion,       // Rebasing vs nominal supply
    MarketCapOracleManipulation,   // Market cap calculation exploit
}

pub struct CirculatingSupplyDetector {
    bytecode: Vec<u8>,
}

impl CirculatingSupplyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CirculatingSupplyVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.tracks_circulating_supply() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_supply_calculation_issues());
        vulnerabilities.extend(self.detect_burn_address_issues());

        vulnerabilities
    }

    fn detect_supply_calculation_issues(&self) -> Vec<CirculatingSupplyVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.calculates_circulating_supply(i) && !self.excludes_locked_tokens(i) {
                vulnerabilities.push(CirculatingSupplyVulnerability {
                    vulnerability_type: CirculatingSupplyIssueType::LockedTokensNotCounted,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "Circulating supply calculation includes locked tokens".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract calculates circulating supply\n\
                        2. Locked/vesting tokens included\n\
                        3. Supply appears higher than reality\n\
                        4. Market cap manipulation or incorrect pricing\n\n\
                        Fix: Subtract locked/vesting balances from supply",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_burn_address_issues(&self) -> Vec<CirculatingSupplyVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.calculates_total_supply(i) && !self.excludes_burn_address(i) {
                vulnerabilities.push(CirculatingSupplyVulnerability {
                    vulnerability_type: CirculatingSupplyIssueType::BurnAddressNotExcluded,
                    severity: SecuritySeverity::Low,
                    confidence: 0.65,
                    description: "Total supply calculation includes burn address".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Total supply includes burned tokens\n\
                        2. Burn address (0x000...dead) counted\n\
                        3. Inflated supply metric\n\
                        4. Inaccurate market data\n\n\
                        Fix: Exclude burn addresses from supply",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn tracks_circulating_supply(&self) -> bool {
        let total_supply = [0x18, 0x16, 0x0d, 0xdd]; // totalSupply()
        let circulating = [0x9a, 0x7a, 0x23, 0xd6]; // circulatingSupply()
        self.bytecode.windows(4).any(|w| w == total_supply || w == circulating)
    }

    fn calculates_circulating_supply(&self, pos: usize) -> bool {
        // Look for SUB operation (total - locked)
        pos + 5 < self.bytecode.len() && self.bytecode[pos] == 0x03 // SUB
    }

    fn excludes_locked_tokens(&self, pos: usize) -> bool {
        // Look for multiple SLOAD (checking locked balances)
        let sload_count = self.bytecode[pos.saturating_sub(30)..pos]
            .iter()
            .filter(|&&b| b == 0x54)
            .count();
        sload_count >= 2
    }

    fn calculates_total_supply(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn excludes_burn_address(&self, pos: usize) -> bool {
        // Look for burn address check (0x000...dead)
        for i in pos.saturating_sub(40)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() && self.bytecode[i+1] == 0x00 {
                return true;
            }
        }
        false
    }
}
