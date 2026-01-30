/// Cross-Contract Withdrawal Cascade Detector
///
/// Detects vulnerabilities where coordinated withdrawals across multiple
/// protocols can trigger cascading failures and bank run scenarios.
///
/// Examples:
/// - Terra/Luna: Anchor withdrawals cascaded to Luna depegging ($40B)
/// - Silicon Valley Bank of DeFi: Coordinated runs across lending protocols
/// - Withdrawal queue manipulation across integrated protocols
/// - Cross-protocol liquidity crunches
///
/// Real exploits: Terra/Luna ($40B), Iron Finance ($1B TVL collapse)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractWithdrawalCascadeVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub cascade_type: WithdrawalCascadeType,
    pub amplification_risk: String,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WithdrawalCascadeType {
    /// Withdrawal triggering external protocol withdrawals
    ChainedWithdrawals,
    /// Withdrawal queue dependency across protocols
    QueueDependency,
    /// Liquidity crisis propagation
    LiquidityCrisis,
    /// Reserve ratio cascade failures
    ReserveRatioCascade,
    /// Bank run coordination across protocols
    CoordinatedBankRun,
}

pub struct CrossContractWithdrawalCascadeAnalyzer;

impl CrossContractWithdrawalCascadeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractWithdrawalCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_chained_withdrawals(bytecode) {
            vulnerabilities.push(CrossContractWithdrawalCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Withdrawal triggers external protocol withdrawals without rate limiting".to_string(),
                location: "Withdrawal logic".to_string(),
                cascade_type: WithdrawalCascadeType::ChainedWithdrawals,
                amplification_risk: "N-protocol cascade".to_string(),
                impact: "Single large withdrawal can trigger multi-protocol liquidity crisis".to_string(),
            });
        }

        if self.has_withdrawal_queue_dependency(bytecode) {
            vulnerabilities.push(CrossContractWithdrawalCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Withdrawal queue state shared or dependent across protocols".to_string(),
                location: "Queue management".to_string(),
                cascade_type: WithdrawalCascadeType::QueueDependency,
                amplification_risk: "Queue congestion cascade".to_string(),
                impact: "Queue manipulation in one protocol affects all dependent protocols".to_string(),
            });
        }

        if self.has_liquidity_crisis_propagation(bytecode) {
            vulnerabilities.push(CrossContractWithdrawalCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Liquidity crisis in one protocol cascades to others".to_string(),
                location: "Liquidity check".to_string(),
                cascade_type: WithdrawalCascadeType::LiquidityCrisis,
                amplification_risk: "Exponential".to_string(),
                impact: "Illiquidity propagates across all integrated protocols".to_string(),
            });
        }

        if self.has_reserve_ratio_cascade(bytecode) {
            vulnerabilities.push(CrossContractWithdrawalCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Reserve ratio violations cascade across protocol dependencies".to_string(),
                location: "Reserve calculation".to_string(),
                cascade_type: WithdrawalCascadeType::ReserveRatioCascade,
                amplification_risk: "Leverage multiplier".to_string(),
                impact: "Reserve depletion in base protocol affects all dependent protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_chained_withdrawals(&self, bytecode: &[u8]) -> bool {
        // Look for: withdraw function that calls external protocols
        let withdraw_sigs = [
            &[0x2e, 0x1a, 0x7d, 0x4d][..], // withdraw()
            &[0x3c, 0xcf, 0xd6, 0x0b][..], // redeem()
        ];

        withdraw_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // External CALL
            !window.contains(&0x57)   // No rate limit check
        })
    }

    fn has_withdrawal_queue_dependency(&self, bytecode: &[u8]) -> bool {
        // Look for: external queue state queries in withdrawal logic
        bytecode.windows(60).any(|window| {
            window.contains(&0xfa) && // STATICCALL (queue query)
            window.contains(&0x54) && // SLOAD (internal queue)
            window.contains(&0x10) && // LT (comparison)
            window.contains(&0x2e)    // Likely withdraw sig byte
        })
    }

    fn has_liquidity_crisis_propagation(&self, bytecode: &[u8]) -> bool {
        // Look for: liquidity checks based on external protocol state
        let balance_sig = &[0x70, 0xa0, 0x82, 0x31]; // balanceOf()
        
        bytecode.windows(4).any(|w| w == balance_sig) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External balance query
            window.contains(&0x04) && // DIV (ratio calc)
            window.contains(&0x57) && // JUMPI (revert on low liquidity)
            !window.contains(&0x42)   // No time delay protection
        })
    }

    fn has_reserve_ratio_cascade(&self, bytecode: &[u8]) -> bool {
        // Look for: reserve ratio dependent on external protocol reserves
        bytecode.windows(60).any(|window| {
            let external_queries = window.iter().filter(|&&op| op == 0xfa).count();
            external_queries >= 2 && // Multiple external reserve queries
            window.contains(&0x04) && // DIV (ratio)
            window.contains(&0x10)    // LT (threshold check)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractWithdrawalCascadeVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractWithdrawalCascade,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Withdrawal Cascade: {} - Risk: {} - Impact: {}",
                vuln.description, vuln.amplification_risk, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement circuit breakers and withdrawal rate limits", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chained_withdrawals() {
        let analyzer = CrossContractWithdrawalCascadeAnalyzer::new();
        
        let bytecode = vec![
            0x2e, 0x1a, 0x7d, 0x4d, // withdraw()
            0xf1,                     // CALL (external)
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
