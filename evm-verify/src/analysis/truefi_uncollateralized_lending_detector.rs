use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// TrueFi Uncollateralized Lending Default Gaming Detector
/// 
/// Detects vulnerabilities in uncollateralized lending protocols where borrower
/// coordination or credit line manipulation can lead to strategic defaults.
/// 
/// **TrueFi Context**:
/// TrueFi provides uncollateralized loans based on borrower reputation/credit scores.
/// Lenders vote to approve credit lines. Borrowers can default strategically.
/// 
/// **Attack Patterns**:
/// 1. Coordinated default by multiple borrowers
/// 2. Credit line manipulation before default
/// 3. Loan repayment gaming to maintain credit score
/// 4. Borrower identity Sybil attacks
/// 5. Credit assessment manipulation
/// 
/// **Detection Strategy**:
/// - Identifies loan approval without proper credit checks
/// - Detects missing default penalties or blacklisting
/// - Flags credit line increases without validation
/// - Checks for borrower identity verification gaps
/// - Validates loan repayment tracking
pub struct TruefiUncollateralizedLendingDetector {
    bytecode: Vec<u8>,
}

impl TruefiUncollateralizedLendingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_uncollateralized_loan_without_credit_check() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Uncollateralized loan approved without proper credit assessment - TrueFi pattern".to_string(),
                operations: Vec::new(),
                remediation: "Implement robust credit scoring with historical repayment tracking and identity verification".to_string(),
            });
        }

        if self.has_missing_default_penalty() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "No default penalty or blacklisting mechanism for failed repayments".to_string(),
                operations: Vec::new(),
                remediation: "Add permanent blacklist and on-chain reputation damage for defaults".to_string(),
            });
        }

        if self.has_credit_line_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Credit line can be increased without proper validation or voting".to_string(),
                operations: Vec::new(),
                remediation: "Require lender voting and credit reassessment for credit line increases".to_string(),
            });
        }

        if self.has_borrower_identity_gap() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Borrower identity verification insufficient - enables Sybil attacks".to_string(),
                operations: Vec::new(),
                remediation: "Implement strong identity verification (KYC) and prevent address rotation".to_string(),
            });
        }

        warnings
    }

    fn has_uncollateralized_loan_without_credit_check(&self) -> bool {
        // Pattern: borrow() without credit score validation
        let borrow_selector = [0xc5, 0xea, 0xbe, 0xec]; // borrow()
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == borrow_selector {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check for uncollateralized transfer
                    let transfers_without_collateral = window.windows(20).any(|w| {
                        w.iter().any(|&op| op == 0xf1) && // CALL (transfer funds)
                        !w.iter().any(|&op| op == 0x31) // NO BALANCE check (uncollateralized)
                    });
                    
                    // Check for credit score validation
                    let checks_credit_score = window.windows(15).any(|w| {
                        // Pattern: SLOAD(creditScore) -> GT(threshold)
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (credit key)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (score)
                        w.iter().any(|&op| op == 0x11) && // GT (score > min)
                        w.iter().any(|&op| op == 0xfd) // REVERT if too low
                    });
                    
                    // Check for repayment history validation
                    let checks_history = window.windows(12).any(|w| {
                        // Check past loan performance
                        w.iter().filter(|&&op| op == 0x54).count() >= 3 // Multiple SLOAD (history)
                    });
                    
                    // Check for lender approval voting
                    let requires_voting = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x04) && // DIV (vote count / total)
                        w.iter().any(|&op| op == 0x11) // GT (quorum check)
                    });
                    
                    if transfers_without_collateral && !checks_credit_score && !checks_history && !requires_voting {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_default_penalty(&self) -> bool {
        // Check if default handling exists
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for repayment deadline check
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check for deadline comparison
                let checks_deadline = window.windows(8).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (deadline)
                    w.iter().any(|&op| op == 0x11) // GT (past deadline)
                });
                
                if checks_deadline {
                    // Check for default penalty application
                    let has_penalty = window.windows(15).any(|w| {
                        // Pattern: update credit score or blacklist
                        w.iter().any(|&op| op == 0x03) && // SUB (reduce score)
                        w.iter().any(|&op| op == 0x55) // SSTORE (update)
                    });
                    
                    // Check for blacklist addition
                    let has_blacklist = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (blacklist key)
                        w.iter().any(|&op| op == 0x60) && // PUSH1 (true/1)
                        w.iter().any(|&op| op == 0x55) // SSTORE (blacklist)
                    });
                    
                    if !has_penalty && !has_blacklist {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_credit_line_manipulation(&self) -> bool {
        // Pattern: increaseCreditLine() without proper controls
        let increase_credit = [0x8c, 0x39, 0x0f, 0xcc]; // increaseCreditLine()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == increase_credit {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for credit line update
                    let updates_credit_line = window.contains(&0x55); // SSTORE
                    
                    // Check for voting requirement
                    let requires_vote = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x04) && // DIV (vote tally)
                        w.iter().any(|&op| op == 0x11) // GT (quorum)
                    });
                    
                    // Check for credit reassessment
                    let reassesses_credit = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0xfa) && // STATICCALL (credit check)
                        w.iter().any(|&op| op == 0x54) // SLOAD (history)
                    });
                    
                    // Check for collateral requirement increase
                    let requires_more_collateral = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x31) // BALANCE (collateral)
                    });
                    
                    if updates_credit_line && !requires_vote && !reassesses_credit && !requires_more_collateral {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_borrower_identity_gap(&self) -> bool {
        // Pattern: borrower registration without identity verification
        let register_selector = [0x1a, 0xa3, 0xa0, 0x08]; // registerBorrower()
        
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == register_selector {
                    let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                    
                    // Check for borrower registration
                    let registers_borrower = window.contains(&0x55); // SSTORE
                    
                    // Check for KYC verification
                    let has_kyc = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0xfa) && // STATICCALL (KYC provider)
                        w.iter().any(|&op| op == 0x15) // ISZERO (check verified)
                    });
                    
                    // Check for unique identity enforcement
                    let prevents_duplicates = window.windows(12).any(|w| {
                        // Hash identity data to prevent reuse
                        w.iter().any(|&op| op == 0x20) && // KECCAK256
                        w.iter().any(|&op| op == 0x54) && // SLOAD (check existing)
                        w.iter().any(|&op| op == 0x15) // ISZERO (require new)
                    });
                    
                    if registers_borrower && !has_kyc && !prevents_duplicates {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truefi_uncollateralized_loan() {
        let vulnerable_bytecode = vec![
            0x63, 0xc5, 0xea, 0xbe, 0xec, // borrow()
            0xf1, // CALL (transfer - no credit check!)
        ];

        let detector = TruefiUncollateralizedLendingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("credit") || w.description.contains("Uncollateralized")));
    }
}
