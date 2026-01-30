/// Cross-Contract Collateral Double Counting Detector
///
/// Detects vulnerabilities where the same collateral is counted multiple times
/// across different protocols without proper isolation or tracking.
///
/// Examples:
/// - stETH used as collateral in both Aave and MakerDAO simultaneously
/// - Wrapped tokens counted in both wrapper and underlying protocol
/// - LP tokens used across multiple lending platforms
///
/// Real Risk: $50B+ in lending protocols (Aave, Compound, MakerDAO)
/// Attack: Liquidation in one protocol doesn't reflect in others

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractCollateralDoubleCountingVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub double_counting_type: DoubleCountingType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DoubleCountingType {
    /// Same asset counted in multiple protocols
    MultiProtocolCounting,
    /// Wrapped and underlying both counted
    WrapperDoubleCounting,
    /// Derivative and underlying both counted
    DerivativeDoubleCounting,
    /// Cross-protocol position overlap
    PositionOverlap,
}

pub struct CrossContractCollateralDoubleCountingAnalyzer;

impl CrossContractCollateralDoubleCountingAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractCollateralDoubleCountingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_multi_protocol_counting(bytecode) {
            vulnerabilities.push(CrossContractCollateralDoubleCountingVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Collateral value queried from external protocol without checking if already used elsewhere".to_string(),
                location: "Collateral valuation".to_string(),
                double_counting_type: DoubleCountingType::MultiProtocolCounting,
                impact: "Same collateral counted multiple times enables over-leveraging".to_string(),
            });
        }

        if self.has_wrapper_double_counting(bytecode) {
            vulnerabilities.push(CrossContractCollateralDoubleCountingVulnerability {
                severity: SecuritySeverity::High,
                description: "Wrapped and underlying token both accepted without mutual exclusion".to_string(),
                location: "Token acceptance logic".to_string(),
                double_counting_type: DoubleCountingType::WrapperDoubleCounting,
                impact: "Users can deposit wETH and ETH as separate collateral".to_string(),
            });
        }

        if self.has_derivative_double_counting(bytecode) {
            vulnerabilities.push(CrossContractCollateralDoubleCountingVulnerability {
                severity: SecuritySeverity::High,
                description: "Derivative token collateral doesn't check underlying usage".to_string(),
                location: "Derivative handling".to_string(),
                double_counting_type: DoubleCountingType::DerivativeDoubleCounting,
                impact: "stETH + ETH both usable as collateral simultaneously".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_multi_protocol_counting(&self, bytecode: &[u8]) -> bool {
        // Look for: external balance query without cross-protocol dedup check
        let balance_sig = &[0x70, 0xa0, 0x82, 0x31]; // balanceOf()
        
        bytecode.windows(4).any(|w| w == balance_sig) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External call
            window.contains(&0x02) && // MUL (value calc)
            !window.contains(&0x14)   // No EQ (no dedup check)
        })
    }

    fn has_wrapper_double_counting(&self, bytecode: &[u8]) -> bool {
        // Look for: accepting multiple token types without checking relationships
        bytecode.windows(60).any(|window| {
            let balance_checks = window.windows(4).filter(|w| w == &[0x70, 0xa0, 0x82, 0x31]).count();
            balance_checks >= 2 && // Multiple token balance checks
            !window.contains(&0x14) // No equality/relationship check
        })
    }

    fn has_derivative_double_counting(&self, bytecode: &[u8]) -> bool {
        // Look for: derivative token handling without underlying check
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External derivative query
            window.contains(&0x02) && // Value calculation
            !window.iter().any(|&op| op == 0x54 && op == 0x14) // No storage check for underlying
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractCollateralDoubleCountingVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractCollateralDoubleCounting,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Collateral Double Counting: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement cross-protocol collateral tracking", vuln.location),
        }).collect()
    }
}
