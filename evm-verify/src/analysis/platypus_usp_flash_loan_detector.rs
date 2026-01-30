use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Platypus USP (Ultra Stable Pool) Flash Loan Specific Detector
/// 
/// Detects the specific vulnerability pattern exploited in the Platypus Finance hack
/// where flash loans were used to manipulate USP solvency checks and drain collateral.
/// 
/// **Historical Exploit**: Platypus Finance ($8.5M, February 2023)
/// 
/// **Attack Pattern**:
/// 1. Attacker takes flash loan to inflate their position
/// 2. Deposits collateral to meet solvency requirements temporarily
/// 3. Exploits USP solvency check logic that doesn't account for flash loan debt
/// 4. Borrows/withdraws more than entitled based on manipulated solvency
/// 5. Repays flash loan and profits from over-withdrawal
/// 
/// **Specific Platypus Vulnerability**:
/// The USP solvency calculation checked `coverage ratio = collateral / liabilities`
/// but failed to account for within-transaction flash loan manipulation. The check
/// used instantaneous balances without validating debt obligations would be repaid.
/// 
/// **Detection Strategy**:
/// - Identifies USP-style solvency/coverage ratio calculations
/// - Detects flash loan callbacks followed by solvency checks
/// - Flags missing flash loan debt accounting in coverage calculations
/// - Checks for emergency pause bypass during flash loan operations
/// - Validates collateral withdrawal limits against manipulable ratios
pub struct PlatypusUspFlashLoanDetector {
    bytecode: Vec<u8>,
}

impl PlatypusUspFlashLoanDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_usp_solvency_flash_loan_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::FlashLoanAttackVector,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "USP solvency check vulnerable to flash loan manipulation - Platypus vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Account for outstanding flash loan debt in solvency calculations and add flash loan guards".to_string(),
            });
        }

        if self.has_coverage_ratio_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Coverage ratio calculation uses manipulable instantaneous balances".to_string(),
                operations: Vec::new(),
                remediation: "Use time-weighted balances or snapshot-based coverage ratio calculations".to_string(),
            });
        }

        if self.has_collateral_withdrawal_without_debt_check() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Collateral withdrawal doesn't validate outstanding debt obligations".to_string(),
                operations: Vec::new(),
                remediation: "Add comprehensive debt validation before allowing collateral withdrawals".to_string(),
            });
        }

        if self.has_emergency_pause_bypass_via_flash_loan() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Emergency pause can be bypassed during flash loan execution".to_string(),
                operations: Vec::new(),
                remediation: "Ensure emergency pause blocks all operations including flash loan callbacks".to_string(),
            });
        }

        warnings
    }

    fn has_usp_solvency_flash_loan_manipulation(&self) -> bool {
        // Pattern: flash loan callback -> balance check -> solvency calculation -> borrow/withdraw
        let flash_loan_callback = [0x23, 0xe3, 0x0c, 0x8b]; // onFlashLoan selector
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == flash_loan_callback {
                    let window = &self.bytecode[i..i+80.min(self.bytecode.len())];
                    
                    // Look for balance/coverage check pattern
                    let has_balance_check = window.iter().any(|&op| {
                        op == 0x31 // BALANCE
                    });
                    
                    // Look for division (coverage ratio = collateral / liabilities)
                    let has_ratio_calc = window.iter().any(|&op| {
                        op == 0x04 // DIV
                    });
                    
                    // Look for withdrawal/borrow operation
                    let has_withdrawal = window.iter().any(|&op| {
                        op == 0xf1 || op == 0x55 // CALL or SSTORE (withdrawal)
                    });
                    
                    // Critical: Check if flash loan debt is accounted for
                    let has_debt_accounting = window.windows(6).any(|w| {
                        // Look for: CALLDATALOAD (loan amount) -> ADD (to liabilities) -> SSTORE
                        w[0] == 0x35 && // CALLDATALOAD
                        w.iter().any(|&op| op == 0x01) && // ADD
                        w.iter().any(|&op| op == 0x55) // SSTORE
                    });
                    
                    // Vulnerable if has coverage check + withdrawal but no debt accounting
                    if has_balance_check && has_ratio_calc && has_withdrawal && !has_debt_accounting {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_coverage_ratio_manipulation(&self) -> bool {
        // Pattern: BALANCE / totalSupply without time-weighting or snapshot
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x31 { // BALANCE (collateral)
                let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                
                // Look for division by total supply or liabilities
                let has_division = window.windows(3).any(|w| {
                    (w[0] == 0x18 || w[0] == 0x54) && // TOTALSSUPPLY or SLOAD (liabilities)
                    w[1] == 0x04 // DIV
                });
                
                // Check for comparison (coverage ratio threshold)
                let has_threshold_check = window.iter().any(|&op| {
                    op == 0x10 || op == 0x11 // LT or GT
                });
                
                // Check for time-weighting or snapshot mechanism
                let has_time_weight = window.iter().any(|&op| {
                    op == 0x42 // TIMESTAMP (for TWAP/time-weighted)
                });
                
                // Check for stored historical values (snapshots)
                let has_snapshot = window.windows(5).any(|w| {
                    w[0] == 0x20 && // KECCAK256 (snapshot key)
                    w.iter().any(|&x| x == 0x54) // SLOAD
                });
                
                // Vulnerable if calculates ratio with threshold but no time-weighting
                if has_division && has_threshold_check && !has_time_weight && !has_snapshot {
                    return true;
                }
            }
        }
        false
    }

    fn has_collateral_withdrawal_without_debt_check(&self) -> bool {
        // Pattern: withdraw() without comprehensive debt validation
        let withdraw_selector = [0x2e, 0x1a, 0x7d, 0x4d]; // withdraw()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == withdraw_selector {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Look for collateral transfer
                    let has_transfer = window.iter().any(|&op| {
                        op == 0xf1 // CALL (token transfer)
                    });
                    
                    // Check for debt validation
                    let has_debt_check = window.windows(10).any(|w| {
                        // Pattern: SLOAD (user debt) -> comparison -> JUMPI
                        w.iter().any(|&op| op == 0x54) && // SLOAD
                        w.iter().any(|&op| op == 0x10 || op == 0x11) && // LT/GT
                        w.iter().any(|&op| op == 0x57) // JUMPI (conditional)
                    });
                    
                    // Check for flash loan protection
                    let has_flash_loan_guard = window.windows(5).any(|w| {
                        // Look for same-block check
                        w[0] == 0x43 && // NUMBER (block.number)
                        w.iter().any(|&op| op == 0x54) // SLOAD (last interaction block)
                    });
                    
                    if has_transfer && !has_debt_check && !has_flash_loan_guard {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_emergency_pause_bypass_via_flash_loan(&self) -> bool {
        // Check if flash loan callback can execute when paused
        let flash_callback = [0x23, 0xe3, 0x0c, 0x8b];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == flash_callback {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for pause validation
                    let has_pause_check = window.windows(4).any(|w| {
                        w[0] == 0x54 && // SLOAD (paused flag)
                        w[1] == 0x15 && // ISZERO
                        w[2] == 0x15 && // ISZERO (require not paused)
                        w[3] == 0x57 // JUMPI
                    });
                    
                    // Vulnerable if flash loan callback has no pause check
                    if !has_pause_check {
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
    fn test_platypus_usp_flash_loan_vulnerability() {
        // Simulates Platypus exploit pattern:
        // flash loan -> balance check -> coverage ratio -> withdraw (no debt accounting)
        let vulnerable_bytecode = vec![
            0x63, 0x23, 0xe3, 0x0c, 0x8b, // onFlashLoan callback
            0x31, // BALANCE (check collateral)
            0x54, // SLOAD (load liabilities)
            0x04, // DIV (coverage ratio = collateral / liabilities)
            0x60, 0x64, // PUSH 100 (100% threshold)
            0x11, // GT (ratio > threshold?)
            0x57, // JUMPI (conditional)
            0x63, 0x2e, 0x1a, 0x7d, 0x4d, // withdraw()
            0xf1, // CALL (transfer collateral)
            // NOTE: Missing flash loan debt accounting before ratio check!
        ];

        let detector = PlatypusUspFlashLoanDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty(), "Should detect Platypus USP vulnerability");
        assert!(warnings.iter().any(|w| {
            w.description.contains("USP solvency") || 
            w.description.contains("Coverage ratio")
        }));
    }

    #[test]
    fn test_safe_implementation() {
        // Safe implementation with flash loan debt accounting
        let safe_bytecode = vec![
            0x63, 0x23, 0xe3, 0x0c, 0x8b, // onFlashLoan callback
            0x35, // CALLDATALOAD (get flash loan amount)
            0x54, // SLOAD (load current liabilities)
            0x01, // ADD (liabilities + flash loan debt)
            0x55, // SSTORE (update liabilities with debt)
            0x31, // BALANCE (check collateral)
            0x54, // SLOAD (load updated liabilities)
            0x04, // DIV (coverage ratio with flash loan debt)
            0x60, 0x64, // PUSH 100 (threshold)
            0x11, // GT
            0x57, // JUMPI
        ];

        let detector = PlatypusUspFlashLoanDetector::new(safe_bytecode);
        let warnings = detector.detect();
        
        // Should not detect vulnerability when flash loan debt is properly accounted for
        assert!(warnings.is_empty() || !warnings.iter().any(|w| 
            w.description.contains("USP solvency")
        ));
    }
}
