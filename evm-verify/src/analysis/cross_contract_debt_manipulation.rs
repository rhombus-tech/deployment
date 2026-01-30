/// Cross-Contract Debt Manipulation Detector
///
/// Detects vulnerabilities where debt positions in one protocol
/// can be manipulated to exploit another protocol.
///
/// Examples:
/// - Aave/Compound debt affecting cross-protocol collateral
/// - Flash loan debt manipulation for cross-protocol liquidations
/// - Synthetic debt position gaming
/// - Cross-protocol bad debt socialization
///
/// Real exploits: Mango Markets ($110M), Cream Finance ($130M)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractDebtManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_vector: DebtManipulationVector,
    pub protocols_affected: Vec<String>,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DebtManipulationVector {
    /// Flash loan to inflate debt for liquidation
    FlashLoanDebtInflation,
    /// Cross-protocol collateral/debt ratio manipulation
    CollateralDebtRatioManipulation,
    /// Synthetic debt position gaming
    SyntheticDebtGaming,
    /// Bad debt socialization across protocols
    BadDebtSocialization,
    /// Debt ceiling bypass via cross-protocol routing
    DebtCeilingBypass,
    /// Interest rate manipulation affecting debt
    InterestRateManipulation,
}

pub struct CrossContractDebtManipulationAnalyzer;

impl CrossContractDebtManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractDebtManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_flash_loan_debt_inflation(bytecode) {
            vulnerabilities.push(CrossContractDebtManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Flash loan can inflate debt to manipulate liquidation thresholds".to_string(),
                location: "Debt calculation".to_string(),
                manipulation_vector: DebtManipulationVector::FlashLoanDebtInflation,
                protocols_affected: vec!["Lending protocol".to_string()],
                impact: "Temporary debt inflation triggers unfair liquidations across protocols".to_string(),
            });
        }

        if self.has_collateral_debt_ratio_manipulation(bytecode) {
            vulnerabilities.push(CrossContractDebtManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "External collateral valuation affects debt position".to_string(),
                location: "Collateral ratio calculation".to_string(),
                manipulation_vector: DebtManipulationVector::CollateralDebtRatioManipulation,
                protocols_affected: vec!["Multiple lending protocols".to_string()],
                impact: "Collateral price manipulation enables cross-protocol bad debt creation".to_string(),
            });
        }

        if self.has_synthetic_debt_gaming(bytecode) {
            vulnerabilities.push(CrossContractDebtManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Synthetic debt positions can bypass protocol debt limits".to_string(),
                location: "Synthetic asset minting".to_string(),
                manipulation_vector: DebtManipulationVector::SyntheticDebtGaming,
                protocols_affected: vec!["Synthetic asset protocol".to_string()],
                impact: "Infinite debt creation through cross-protocol synthetic positions".to_string(),
            });
        }

        if self.has_bad_debt_socialization(bytecode) {
            vulnerabilities.push(CrossContractDebtManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Bad debt from one protocol can be socialized to others".to_string(),
                location: "Debt settlement logic".to_string(),
                manipulation_vector: DebtManipulationVector::BadDebtSocialization,
                protocols_affected: vec!["Connected protocols".to_string()],
                impact: "Losses from one protocol cascade to all connected protocols".to_string(),
            });
        }

        if self.has_debt_ceiling_bypass(bytecode) {
            vulnerabilities.push(CrossContractDebtManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Debt ceiling can be bypassed through cross-protocol routing".to_string(),
                location: "Debt limit check".to_string(),
                manipulation_vector: DebtManipulationVector::DebtCeilingBypass,
                protocols_affected: vec!["Multiple protocols".to_string()],
                impact: "Protocol-level debt limits ineffective across integrated systems".to_string(),
            });
        }

        if self.has_interest_rate_manipulation(bytecode) {
            vulnerabilities.push(CrossContractDebtManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Interest rate manipulation affects cross-protocol debt calculations".to_string(),
                location: "Interest rate query".to_string(),
                manipulation_vector: DebtManipulationVector::InterestRateManipulation,
                protocols_affected: vec!["Rate-dependent protocols".to_string()],
                impact: "Manipulated rates cause incorrect debt accrual across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_flash_loan_debt_inflation(&self, bytecode: &[u8]) -> bool {
        // Look for: flash loan + borrow operation + liquidation trigger
        let flash_loan_sigs = [
            &[0x5c, 0xf1, 0x49, 0xee][..], // flashLoan()
            &[0xab, 0x9c, 0x4b, 0x5d][..], // flashBorrow()
        ];

        let borrow_sig = &[0xc5, 0xea, 0xbe, 0xc0]; // borrow()

        flash_loan_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && bytecode.windows(4).any(|w| w == borrow_sig)
    }

    fn has_collateral_debt_ratio_manipulation(&self, bytecode: &[u8]) -> bool {
        // Look for: external price oracle + debt calculation
        let get_price_sigs = [
            &[0x41, 0x97, 0x6e, 0x09][..], // latestAnswer()
            &[0xfe, 0xaf, 0x96, 0x8c][..], // latestRoundData()
        ];

        get_price_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && bytecode.windows(30).any(|window| {
            window.contains(&0x04) && // DIV (ratio calculation)
            window.contains(&0x10)    // LT (threshold check)
        })
    }

    fn has_synthetic_debt_gaming(&self, bytecode: &[u8]) -> bool {
        // Look for: mint synthetic + external collateral query
        let mint_sig = &[0x40, 0xc1, 0x0f, 0x19]; // mint()
        
        bytecode.windows(4).any(|w| w == mint_sig) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External collateral check
            window.contains(&0x02) && // MUL (debt calculation)
            !window.contains(&0x11)   // No GT (no upper limit check)
        })
    }

    fn has_bad_debt_socialization(&self, bytecode: &[u8]) -> bool {
        // Look for: external debt query + internal debt update
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External debt query
            window.contains(&0x54) && // SLOAD (internal debt)
            window.contains(&0x01) && // ADD (combine debts)
            window.contains(&0x55)    // SSTORE (update internal)
        })
    }

    fn has_debt_ceiling_bypass(&self, bytecode: &[u8]) -> bool {
        // Look for: debt limit check + external borrow
        bytecode.windows(60).any(|window| {
            window.contains(&0x11) && // GT (debt limit check)
            window.contains(&0x57) && // JUMPI (check jump)
            window.contains(&0xf1)    // External call (bypass via external)
        })
    }

    fn has_interest_rate_manipulation(&self, bytecode: &[u8]) -> bool {
        // Look for: external interest rate query + debt accrual
        let borrow_rate_sigs = [
            &[0x1f, 0x1f, 0xfa, 0x46][..], // borrowRatePerBlock()
            &[0x18, 0x2d, 0xf0, 0xf5][..], // getBorrowRate()
        ];

        borrow_rate_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && bytecode.contains(&0x02) // MUL (interest calc)
          && !bytecode.windows(20).any(|w| {
              // No bounds check on rate
              w.contains(&0x10) && w.contains(&0x57) // LT + JUMPI
          })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractDebtManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractDebtManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Debt Manipulation: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement flash loan protections and debt ceiling checks", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_loan_debt_inflation() {
        let analyzer = CrossContractDebtManipulationAnalyzer::new();
        
        let bytecode = vec![
            0x5c, 0xf1, 0x49, 0xee, // flashLoan()
            0xc5, 0xea, 0xbe, 0xc0, // borrow()
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_collateral_debt_ratio_manipulation() {
        let analyzer = CrossContractDebtManipulationAnalyzer::new();
        
        let bytecode = vec![
            0x41, 0x97, 0x6e, 0x09, // latestAnswer()
            0x04,                     // DIV
            0x10,                     // LT
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
