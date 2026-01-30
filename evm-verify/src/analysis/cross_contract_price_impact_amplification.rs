/// Cross-Contract Price Impact Amplification Detector
///
/// Detects vulnerabilities where price impact in one protocol is amplified
/// through dependent protocols, enabling manipulation attacks.
///
/// Examples:
/// - Curve pool manipulation amplifying Convex positions
/// - Small AMM pools affecting large lending protocol collateral values
/// - DEX aggregator manipulation cascading across protocols
///
/// Real exploits: Mango Markets ($110M), Avi Eisenberg attacks
/// Risk: $10B+ in Curve/Convex ecosystem alone

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractPriceImpactAmplificationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub amplification_type: PriceImpactAmplificationType,
    pub amplification_factor: String,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PriceImpactAmplificationType {
    /// Small pool manipulation affecting large positions
    SmallPoolLargeImpact,
    /// Leverage amplification across protocols
    LeverageAmplification,
    /// Cascading price impact through dependencies
    CascadingPriceImpact,
    /// Liquidity concentration vulnerability
    LiquidityConcentrationRisk,
    /// Price impact not isolated between protocols
    UnboundedPriceImpact,
}

pub struct CrossContractPriceImpactAmplificationAnalyzer;

impl CrossContractPriceImpactAmplificationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractPriceImpactAmplificationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_small_pool_large_impact(bytecode) {
            vulnerabilities.push(CrossContractPriceImpactAmplificationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Small external pool price used for large position valuation".to_string(),
                location: "Price impact calculation".to_string(),
                amplification_type: PriceImpactAmplificationType::SmallPoolLargeImpact,
                amplification_factor: "Pool size / Position size".to_string(),
                impact: "Manipulating small pool can affect disproportionately large positions".to_string(),
            });
        }

        if self.has_leverage_amplification(bytecode) {
            vulnerabilities.push(CrossContractPriceImpactAmplificationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Leveraged positions amplify external price impact".to_string(),
                location: "Leverage calculation".to_string(),
                amplification_type: PriceImpactAmplificationType::LeverageAmplification,
                amplification_factor: "Leverage multiplier".to_string(),
                impact: "Small external price change liquidates leveraged positions".to_string(),
            });
        }

        if self.has_cascading_price_impact(bytecode) {
            vulnerabilities.push(CrossContractPriceImpactAmplificationVulnerability {
                severity: SecuritySeverity::High,
                description: "Price impact cascades through protocol dependencies".to_string(),
                location: "Price propagation".to_string(),
                amplification_type: PriceImpactAmplificationType::CascadingPriceImpact,
                amplification_factor: "Dependency chain length".to_string(),
                impact: "Price manipulation amplifies through each protocol layer".to_string(),
            });
        }

        if self.has_unbounded_price_impact(bytecode) {
            vulnerabilities.push(CrossContractPriceImpactAmplificationVulnerability {
                severity: SecuritySeverity::High,
                description: "No circuit breakers for cross-protocol price impact".to_string(),
                location: "Price bounds check".to_string(),
                amplification_type: PriceImpactAmplificationType::UnboundedPriceImpact,
                amplification_factor: "Unbounded".to_string(),
                impact: "Extreme price swings propagate unchecked across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_small_pool_large_impact(&self, bytecode: &[u8]) -> bool {
        // Look for: external price query + large value calculation without liquidity check
        bytecode.windows(60).any(|window| {
            window.contains(&0xfa) && // STATICCALL (price query)
            window.contains(&0x02) && // MUL (value calc)
            !window.contains(&0x70) && // No balanceOf (liquidity check)
            window.iter().filter(|&&op| op == 0x02).count() >= 2 // Multiple multiplications
        })
    }

    fn has_leverage_amplification(&self, bytecode: &[u8]) -> bool {
        // Look for: leverage factor + external price without impact limiting
        bytecode.windows(50).any(|window| {
            window.contains(&0x02) && // MUL (leverage)
            window.contains(&0xfa) && // External price
            window.contains(&0x04) && // DIV (collateral ratio)
            !window.contains(&0x11)   // No GT (no max leverage check)
        })
    }

    fn has_cascading_price_impact(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple external price queries in sequence
        let price_calls: Vec<usize> = bytecode.windows(4)
            .enumerate()
            .filter(|(_, w)| {
                w == &[0x50, 0xd2, 0x5b, 0xcd] || // latestAnswer
                w == &[0xfe, 0xaf, 0x96, 0x8c]    // latestRoundData
            })
            .map(|(i, _)| i)
            .collect();

        price_calls.len() >= 2 && // Multiple price sources
        bytecode.contains(&0x02)   // Used in calculation
    }

    fn has_unbounded_price_impact(&self, bytecode: &[u8]) -> bool {
        // Look for: price usage without deviation or circuit breaker checks
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External price call
            window.contains(&0x02) && // Used in MUL
            !window.contains(&0x10) && // No LT (lower bound)
            !window.contains(&0x11)   // No GT (upper bound)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractPriceImpactAmplificationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractPriceImpactAmplification,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Price Impact Amplification: {} - Factor: {} - Impact: {}",
                vuln.description, vuln.amplification_factor, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement liquidity checks and price impact limits", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_pool_large_impact() {
        let analyzer = CrossContractPriceImpactAmplificationAnalyzer::new();
        
        let bytecode = vec![
            0xfa, // STATICCALL (price)
            0x02, // MUL
            0x02, // MUL (amplification)
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
