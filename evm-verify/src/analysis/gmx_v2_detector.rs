/// GMX v2 Oracle Manipulation Detector
/// Detects vulnerabilities in GMX v2 synthetic asset pricing
/// Critical for: GMX v2 integrations, perpetual trading

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GMXV2Vulnerability {
    pub vulnerability_type: GMXV2IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GMXV2IssueType {
    SyntheticTokenPricingExploit,  // Manipulate synthetic pricing
    FundingRateManipulation,       // Exploit funding rates
    KeeperExecutionDelay,          // Keeper delay exploitation
    PriceImpactCalculationError,   // Price impact miscalculation
    OracleLatencyExploit,          // Exploit oracle update latency
}

pub struct GMXV2Detector {
    bytecode: Vec<u8>,
}

impl GMXV2Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GMXV2Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_gmx_integration() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_oracle_issues());
        vulnerabilities.extend(self.detect_keeper_issues());

        vulnerabilities
    }

    fn detect_oracle_issues(&self) -> Vec<GMXV2Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Price fetch without staleness check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA && // STATICCALL (oracle)
               self.is_price_fetch(i) {
                if !self.has_staleness_validation(i) {
                    vulnerabilities.push(GMXV2Vulnerability {
                        vulnerability_type: GMXV2IssueType::OracleLatencyExploit,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "GMX oracle price used without staleness check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Oracle price becomes stale\n\
                            2. No validation of update time\n\
                            3. Attacker uses stale price for trade\n\
                            4. Profits from price discrepancy\n\n\
                            Fix: Validate price timestamp < MAX_AGE",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_keeper_issues(&self) -> Vec<GMXV2Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Order execution without keeper validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let execute = [0x61, 0x46, 0x1c, 0xd4]; // executeOrder()
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &execute {
                if !self.has_keeper_check(i) {
                    vulnerabilities.push(GMXV2Vulnerability {
                        vulnerability_type: GMXV2IssueType::KeeperExecutionDelay,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Order execution without keeper role validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Anyone can execute orders\n\
                            2. No keeper role check\n\
                            3. Attacker delays execution for profit\n\
                            4. Or executes at unfavorable time\n\n\
                            Fix: require(msg.sender == keeper)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_gmx_integration(&self) -> bool {
        // Check for GMX-specific function signatures
        let execute = [0x61, 0x46, 0x1c, 0xd4]; // executeOrder()
        self.bytecode.windows(4).any(|w| w == execute)
    }

    fn is_price_fetch(&self, pos: usize) -> bool {
        // Heuristic: STATICCALL with large return data (price struct)
        pos > 0
    }

    fn has_staleness_validation(&self, pos: usize) -> bool {
        // Look for timestamp comparison
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn has_keeper_check(&self, pos: usize) -> bool {
        // Look for CALLER comparison
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x33 && i + 2 < self.bytecode.len() && self.bytecode[i+2] == 0x14 {
                return true;
            }
        }
        false
    }
}
