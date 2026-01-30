/// Cross-Contract Oracle Staleness Cascade Detector
///
/// Detects vulnerabilities where stale oracle data propagates across
/// multiple protocols, creating cascading price failures.
///
/// Examples:
/// - Venus Protocol: Chainlink oracle staleness affecting liquidations
/// - Compound/Aave: Shared oracle staleness cascading
/// - Cross-DEX price manipulation via stale oracles
///
/// Risk: $100B+ in oracle-dependent DeFi

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractOracleStalenessCascadeVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub cascade_type: OracleStalenessCascadeType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OracleStalenessCascadeType {
    /// Stale price data propagates across protocols
    StalePricePropagation,
    /// No staleness check before using external oracle
    UnvalidatedOracleData,
    /// Circular oracle dependency
    CircularOracleDependency,
    /// Timestamp-based staleness not checked
    TimestampStaleness,
    /// Heartbeat violation cascade
    HeartbeatViolation,
}

pub struct CrossContractOracleStalenessCascadeAnalyzer;

impl CrossContractOracleStalenessCascadeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractOracleStalenessCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_stale_price_propagation(bytecode) {
            vulnerabilities.push(CrossContractOracleStalenessCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Oracle price used from external protocol without staleness validation".to_string(),
                location: "Price feed usage".to_string(),
                cascade_type: OracleStalenessCascadeType::StalePricePropagation,
                impact: "Stale prices from one protocol affect all dependent protocols".to_string(),
            });
        }

        if self.has_unvalidated_oracle_data(bytecode) {
            vulnerabilities.push(CrossContractOracleStalenessCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "External oracle data used without timestamp or round ID validation".to_string(),
                location: "Oracle integration".to_string(),
                cascade_type: OracleStalenessCascadeType::UnvalidatedOracleData,
                impact: "Arbitrarily old price data can be used in critical calculations".to_string(),
            });
        }

        if self.has_circular_oracle_dependency(bytecode) {
            vulnerabilities.push(CrossContractOracleStalenessCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Circular oracle dependencies between protocols".to_string(),
                location: "Oracle dependency chain".to_string(),
                cascade_type: OracleStalenessCascadeType::CircularOracleDependency,
                impact: "Oracle failure cascade loops through protocol dependencies".to_string(),
            });
        }

        if self.has_heartbeat_violation(bytecode) {
            vulnerabilities.push(CrossContractOracleStalenessCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Oracle heartbeat not validated across protocol calls".to_string(),
                location: "Heartbeat check".to_string(),
                cascade_type: OracleStalenessCascadeType::HeartbeatViolation,
                impact: "Long oracle update delays go undetected across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_stale_price_propagation(&self, bytecode: &[u8]) -> bool {
        // Look for: external price query without timestamp check
        let oracle_sigs = [
            &[0x50, 0xd2, 0x5b, 0xcd][..], // latestAnswer()
            &[0xfe, 0xaf, 0x96, 0x8c][..], // latestRoundData()
        ];

        oracle_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && !bytecode.windows(30).any(|window| {
            window.contains(&0x42) // No TIMESTAMP check
        })
    }

    fn has_unvalidated_oracle_data(&self, bytecode: &[u8]) -> bool {
        // Look for: oracle call without validating updatedAt
        bytecode.windows(50).any(|window| {
            window.contains(&0xfe) && // latestRoundData first byte
            window.contains(&0xfa) && // STATICCALL
            !window.contains(&0x03) && // No SUB (no time diff calc)
            window.contains(&0x02)    // MUL (using price directly)
        })
    }

    fn has_circular_oracle_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple oracle queries in dependency chain
        let oracle_calls: Vec<usize> = bytecode.windows(4)
            .enumerate()
            .filter(|(_, w)| {
                w == &[0x50, 0xd2, 0x5b, 0xcd] || // latestAnswer
                w == &[0xfe, 0xaf, 0x96, 0x8c]    // latestRoundData
            })
            .map(|(i, _)| i)
            .collect();

        oracle_calls.len() >= 3 // 3+ oracle calls suggests circular dependency
    }

    fn has_heartbeat_violation(&self, bytecode: &[u8]) -> bool {
        // Look for: no heartbeat interval check
        bytecode.windows(4).any(|w| {
            w == &[0xfe, 0xaf, 0x96, 0x8c] // latestRoundData()
        }) && !bytecode.windows(40).any(|window| {
            // No heartbeat validation pattern
            window.contains(&0x42) && // TIMESTAMP
            window.contains(&0x03) && // SUB (time diff)
            window.contains(&0x10)    // LT (heartbeat check)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractOracleStalenessCascadeVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractOracleStalenessCascade,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Oracle Staleness Cascade: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Validate oracle timestamps and implement heartbeat checks", vuln.location),
        }).collect()
    }
}
