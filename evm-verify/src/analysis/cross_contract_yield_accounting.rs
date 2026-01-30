/// Cross-Contract Yield/Reward Accounting Manipulation Detector
///
/// Detects vulnerabilities where reward/yield calculations in one protocol
/// can be manipulated through state changes in another protocol.
///
/// Examples:
/// - Convex boosting Curve rewards (manipulating Curve affects Convex yields)
/// - Yearn vault yields dependent on Aave/Compound rates
/// - Staking rewards calculated from external AMM prices
/// - Cross-protocol incentive gaming
///
/// Real exploits: Rari Capital ($80M), Harvest Finance ($24M)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractYieldAccountingVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub affected_protocols: Vec<String>,
    pub manipulation_vector: YieldManipulationVector,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum YieldManipulationVector {
    /// External protocol state affects local yield calculation
    ExternalStateDependent,
    /// Reward rate calculated from manipulable oracle
    ManipulableRateOracle,
    /// Cross-protocol share price dependency
    SharePriceDependency,
    /// External balance affects reward distribution
    ExternalBalanceInfluence,
    /// Multi-hop yield calculation vulnerability
    CompoundedYieldChain,
    /// Time-weighted average manipulation across protocols
    TWAPManipulation,
}

pub struct CrossContractYieldAccountingAnalyzer;

impl CrossContractYieldAccountingAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractYieldAccountingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for external state-dependent yield calculations
        if self.has_external_yield_dependency(bytecode) {
            vulnerabilities.push(CrossContractYieldAccountingVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Yield calculation depends on external protocol state that can be manipulated".to_string(),
                location: "Reward calculation logic".to_string(),
                affected_protocols: vec!["External DeFi".to_string()],
                manipulation_vector: YieldManipulationVector::ExternalStateDependent,
                impact: "Attacker can inflate/deflate rewards by manipulating external protocol state".to_string(),
            });
        }

        // Check for manipulable rate oracles
        if self.has_manipulable_rate_oracle(bytecode) {
            vulnerabilities.push(CrossContractYieldAccountingVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Reward rate fetched from manipulable external oracle".to_string(),
                location: "Oracle integration".to_string(),
                affected_protocols: vec!["Price oracle".to_string()],
                manipulation_vector: YieldManipulationVector::ManipulableRateOracle,
                impact: "Flash loan attack can manipulate oracle to extract inflated rewards".to_string(),
            });
        }

        // Check for share price dependency vulnerabilities
        if self.has_share_price_dependency(bytecode) {
            vulnerabilities.push(CrossContractYieldAccountingVulnerability {
                severity: SecuritySeverity::High,
                description: "Local rewards calculated based on external vault share price".to_string(),
                location: "Share price calculation".to_string(),
                affected_protocols: vec!["External vault".to_string()],
                manipulation_vector: YieldManipulationVector::SharePriceDependency,
                impact: "Share price manipulation in external vault affects local reward distribution".to_string(),
            });
        }

        // Check for external balance influence
        if self.has_external_balance_influence(bytecode) {
            vulnerabilities.push(CrossContractYieldAccountingVulnerability {
                severity: SecuritySeverity::High,
                description: "Reward distribution influenced by external protocol balances".to_string(),
                location: "Balance query".to_string(),
                affected_protocols: vec!["External protocol".to_string()],
                manipulation_vector: YieldManipulationVector::ExternalBalanceInfluence,
                impact: "Temporary balance manipulation can steal disproportionate rewards".to_string(),
            });
        }

        // Check for compounded yield chain vulnerabilities
        if self.has_compounded_yield_chain(bytecode) {
            vulnerabilities.push(CrossContractYieldAccountingVulnerability {
                severity: SecuritySeverity::High,
                description: "Multi-hop yield calculation amplifies manipulation effects".to_string(),
                location: "Nested yield calculation".to_string(),
                affected_protocols: vec!["Multiple protocols".to_string()],
                manipulation_vector: YieldManipulationVector::CompoundedYieldChain,
                impact: "Small manipulation in base protocol cascades through yield chain".to_string(),
            });
        }

        // Check for TWAP manipulation across protocols
        if self.has_cross_protocol_twap(bytecode) {
            vulnerabilities.push(CrossContractYieldAccountingVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Time-weighted average calculation vulnerable to cross-protocol manipulation".to_string(),
                location: "TWAP calculation".to_string(),
                affected_protocols: vec!["Multiple AMMs".to_string()],
                manipulation_vector: YieldManipulationVector::TWAPManipulation,
                impact: "Multi-block attack can skew TWAP-based reward calculations".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_external_yield_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for patterns: external call + arithmetic + storage write (reward calculation)
        // CALL/STATICCALL -> MUL/DIV -> SSTORE
        bytecode.windows(20).any(|window| {
            window.contains(&0xf1) && // CALL
            window.contains(&0x02) && // MUL
            window.contains(&0x55)    // SSTORE
        }) || bytecode.windows(20).any(|window| {
            window.contains(&0xfa) && // STATICCALL  
            window.contains(&0x04) && // DIV
            window.contains(&0x55)    // SSTORE
        })
    }

    fn has_manipulable_rate_oracle(&self, bytecode: &[u8]) -> bool {
        // Look for: external call for rate + no validation + direct use in rewards
        // Pattern: STATICCALL (rate fetch) -> immediate arithmetic without checks
        bytecode.windows(15).any(|window| {
            window.contains(&0xfa) && // STATICCALL
            !window.contains(&0x57) && // No JUMPI (no validation)
            (window.contains(&0x02) || window.contains(&0x04)) // MUL or DIV
        })
    }

    fn has_share_price_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for: external share price call + reward calculation
        // Signature patterns for getSharePrice, pricePerShare, etc.
        let share_price_sigs = [
            &[0x99, 0x53, 0x0b, 0x06][..], // getSharePrice()
            &[0x77, 0xc7, 0xb8, 0xfc][..], // pricePerShare()
        ];

        share_price_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && bytecode.contains(&0x02) // and has MUL (reward calculation)
    }

    fn has_external_balance_influence(&self, bytecode: &[u8]) -> bool {
        // Look for: balanceOf external call + reward distribution logic
        let balance_sig = &[0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
        
        bytecode.windows(4).any(|w| w == balance_sig) &&
        bytecode.windows(20).any(|window| {
            window.contains(&0xf1) && // CALL (balanceOf)
            window.contains(&0x04) && // DIV (reward distribution)
            window.contains(&0x55)    // SSTORE (update rewards)
        })
    }

    fn has_compounded_yield_chain(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple external yield calls in sequence
        // Count STATICCALL/CALL opcodes near each other
        let external_calls: Vec<usize> = bytecode.iter()
            .enumerate()
            .filter(|(_, &op)| op == 0xf1 || op == 0xfa)
            .map(|(i, _)| i)
            .collect();

        // Check for 2+ external calls within 100 bytes (likely nested yields)
        external_calls.windows(2).any(|pair| {
            pair[1] - pair[0] < 100
        })
    }

    fn has_cross_protocol_twap(&self, bytecode: &[u8]) -> bool {
        // Look for: timestamp usage + multiple external calls + averaging
        bytecode.contains(&0x42) && // TIMESTAMP
        bytecode.windows(50).filter(|w| w.contains(&0xfa)).count() >= 2 && // Multiple STATICCALL
        bytecode.contains(&0x04) && // DIV (averaging)
        bytecode.contains(&0x01)    // ADD (accumulation)
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractYieldAccountingVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractYieldManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Yield Manipulation: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Ensure yields cannot be manipulated through external state", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_yield_dependency() {
        let analyzer = CrossContractYieldAccountingAnalyzer::new();
        
        // Bytecode with external call -> MUL -> SSTORE pattern
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0xf1,       // CALL (external)
            0x02,       // MUL (calculate reward)
            0x55,       // SSTORE (save reward)
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(
            v.manipulation_vector,
            YieldManipulationVector::ExternalStateDependent
        )));
    }

    #[test]
    fn test_share_price_dependency() {
        let analyzer = CrossContractYieldAccountingAnalyzer::new();
        
        // Bytecode with pricePerShare signature + MUL
        let bytecode = vec![
            0x77, 0xc7, 0xb8, 0xfc, // pricePerShare() signature
            0x02,                     // MUL
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
