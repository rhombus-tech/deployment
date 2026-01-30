/// Cross-Protocol Perpetual Funding Rate Manipulation Detector
///
/// Detects funding rate manipulation across perpetual platforms.
/// Risk: dYdX, GMX, Drift, Hyperliquid ($50B+ in perps)
/// Attack: Exploit funding rate differentials across platforms

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolPerpetualFundingRateVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub funding_manipulation: FundingRateManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FundingRateManipulationType {
    FundingRateArbitrage,
    CrossPlatformRateManipulation,
    FundingPaymentDesync,
    OpenInterestManipulation,
}

pub struct CrossProtocolPerpetualFundingRateAnalyzer;

impl CrossProtocolPerpetualFundingRateAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolPerpetualFundingRateVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_funding_rate_arbitrage(bytecode) {
            vulnerabilities.push(CrossProtocolPerpetualFundingRateVulnerability {
                severity: SecuritySeverity::High,
                description: "Funding rates not synchronized across perpetual platforms".to_string(),
                location: "Funding rate calculation".to_string(),
                funding_manipulation: FundingRateManipulationType::FundingRateArbitrage,
                impact: "Long on dYdX (negative funding), short on GMX (positive funding) for profit".to_string(),
            });
        }

        if self.has_cross_platform_manipulation(bytecode) {
            vulnerabilities.push(CrossProtocolPerpetualFundingRateVulnerability {
                severity: SecuritySeverity::High,
                description: "Funding rate manipulated to affect other platforms".to_string(),
                location: "Rate manipulation".to_string(),
                funding_manipulation: FundingRateManipulationType::CrossPlatformRateManipulation,
                impact: "Manipulate GMX funding to profit from hedged position on Hyperliquid".to_string(),
            });
        }

        if self.has_funding_payment_desync(bytecode) {
            vulnerabilities.push(CrossProtocolPerpetualFundingRateVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Funding payments occur at different times across platforms".to_string(),
                location: "Payment timing".to_string(),
                funding_manipulation: FundingRateManipulationType::FundingPaymentDesync,
                impact: "Receive payment on Platform A before paying on Platform B".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_funding_rate_arbitrage(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(80).any(|window| {
            window.iter().filter(|&&op| op == 0xfa).count() >= 2 && // Multiple funding rate queries
            !window.contains(&0x14) && // No rate consistency check
            window.contains(&0x03)     // Arbitrage calculation
        })
    }

    fn has_cross_platform_manipulation(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(90).any(|window| {
            window.contains(&0x55) && // Funding rate state change
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-platform
            !window.contains(&0x10) // No manipulation bounds
        })
    }

    fn has_funding_payment_desync(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x42) && // Timestamp
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-platform
            !window.contains(&0x14) // No timing synchronization
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolPerpetualFundingRateVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolPerpetualFundingRate,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Perpetual Funding Rate: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement funding rate synchronization and arbitrage detection", vuln.location),
        }).collect()
    }
}
