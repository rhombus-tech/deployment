/// Cross-Protocol Rate Limiting Bypass Detector
///
/// Detects rate limit bypasses across integrated protocols.
/// Risk: All rate-limited protocols (withdrawals, borrows, mints)
/// Attack: Hit limit on Protocol A, continue on Protocol B

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolRateLimitingBypassVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub bypass_type: RateLimitBypassType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitBypassType {
    PerProtocolLimitBypass,
    GlobalLimitNotEnforced,
    TimeWindowDesynchronization,
    AggregatedLimitMissing,
}

pub struct CrossProtocolRateLimitingBypassAnalyzer;

impl CrossProtocolRateLimitingBypassAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolRateLimitingBypassVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_per_protocol_limit_bypass(bytecode) {
            vulnerabilities.push(CrossProtocolRateLimitingBypassVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Rate limit enforced per-protocol, not globally".to_string(),
                location: "Rate limit enforcement".to_string(),
                bypass_type: RateLimitBypassType::PerProtocolLimitBypass,
                impact: "$1M daily limit bypassed by using 10 protocols for $10M total".to_string(),
            });
        }

        if self.has_global_limit_not_enforced(bytecode) {
            vulnerabilities.push(CrossProtocolRateLimitingBypassVulnerability {
                severity: SecuritySeverity::High,
                description: "No global rate limit tracking across integrated protocols".to_string(),
                location: "Global limit tracking".to_string(),
                bypass_type: RateLimitBypassType::GlobalLimitNotEnforced,
                impact: "User withdraws from Aave and Compound simultaneously exceeding total limit".to_string(),
            });
        }

        if self.has_time_window_desync(bytecode) {
            vulnerabilities.push(CrossProtocolRateLimitingBypassVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Rate limit time windows not synchronized across protocols".to_string(),
                location: "Time window calculation".to_string(),
                bypass_type: RateLimitBypassType::TimeWindowDesynchronization,
                impact: "24-hour window differs by protocol enabling rapid reset exploitation".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_per_protocol_limit_bypass(&self, bytecode: &[u8]) -> bool {
        // Rate limit check without cross-protocol tracking
        bytecode.windows(60).any(|window| {
            window.contains(&0x54) && // Rate limit state read
            window.contains(&0x10) && // Limit comparison
            !window.contains(&0xfa) && // No external protocol query
            window.contains(&0xf1)     // But cross-protocol operation exists
        })
    }

    fn has_global_limit_not_enforced(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple protocols
            window.contains(&0x10) && // Limit check
            !window.contains(&0x01)   // No aggregation (ADD)
        })
    }

    fn has_time_window_desync(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0x42) && // Timestamp
            window.contains(&0x03) && // Time window calculation
            window.contains(&0xf1) && // Cross-protocol
            !window.contains(&0x14)   // No time sync verification
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolRateLimitingBypassVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolRateLimitingBypass,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Rate Limiting Bypass: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement global rate limit tracking across all integrated protocols", vuln.location),
        }).collect()
    }
}
