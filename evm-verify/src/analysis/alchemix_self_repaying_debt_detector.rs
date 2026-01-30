use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Alchemix Self-Repaying Debt Manipulation Detector
/// 
/// Detects vulnerabilities in self-repaying debt mechanisms where yield farming
/// automatically pays down loans, enabling debt token manipulation and liquidation bypass.
/// 
/// **Alchemix Context**:
/// Users deposit yield-bearing assets (e.g., yvDAI) and borrow against future yield.
/// The protocol automatically repays debt using yield generated from deposits.
/// 
/// **Attack Patterns**:
/// 1. Debt token (alUSD/alETH) manipulation to avoid repayment
/// 2. Yield accounting errors enabling over-borrowing
/// 3. Self-liquidation bypass via yield manipulation
/// 4. Transmuter gaming to extract value
/// 5. Debt share dilution attacks
/// 
/// **Detection Strategy**:
/// - Identifies debt repayment without yield validation
/// - Detects missing debt token supply controls
/// - Flags liquidation bypass via yield manipulation
/// - Checks for transmuter exchange rate gaming
/// - Validates debt share calculations
pub struct AlchemixSelfRepayingDebtDetector {
    bytecode: Vec<u8>,
}

impl AlchemixSelfRepayingDebtDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_yield_based_debt_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Self-repaying debt mechanism vulnerable to yield manipulation - Alchemix pattern".to_string(),
                operations: Vec::new(),
                remediation: "Validate yield calculations independently and add debt repayment rate limits".to_string(),
            });
        }

        if self.has_liquidation_bypass_via_yield() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Liquidation can be bypassed by manipulating yield accrual".to_string(),
                operations: Vec::new(),
                remediation: "Ensure liquidation checks use actual debt, not yield-adjusted values".to_string(),
            });
        }

        if self.has_transmuter_rate_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Transmuter exchange rate vulnerable to manipulation".to_string(),
                operations: Vec::new(),
                remediation: "Add exchange rate bounds and TWAP validation for transmuter".to_string(),
            });
        }

        if self.has_debt_share_dilution_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Debt shares can be diluted via coordinated yield claims".to_string(),
                operations: Vec::new(),
                remediation: "Protect debt share calculations from dilution attacks".to_string(),
            });
        }

        warnings
    }

    fn has_yield_based_debt_manipulation(&self) -> bool {
        // Pattern: debt repayment based on yield without validation
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0x03 { // SUB (debt reduction)
                let window = &self.bytecode[i.saturating_sub(45)..i+10.min(self.bytecode.len())];
                
                // Check for yield-based repayment
                let uses_yield_for_repayment = window.windows(20).any(|w| {
                    // Pattern: accrued_yield used to reduce debt
                    w.iter().any(|&op| op == 0x54) && // SLOAD (yield)
                    w.iter().any(|&op| op == 0x03) && // SUB (debt - yield)
                    w.iter().any(|&op| op == 0x55) // SSTORE (update debt)
                });
                
                // Check for independent yield validation
                let validates_yield = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL (verify yield)
                    w.iter().any(|&op| op == 0x14) // EQ (cross-check)
                });
                
                // Check for yield manipulation protection
                let has_manipulation_protection = window.windows(10).any(|w| {
                    // Maximum yield per block/time period
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max yield)
                    w.iter().any(|&op| op == 0x10) // LT
                });
                
                if uses_yield_for_repayment && !validates_yield && !has_manipulation_protection {
                    return true;
                }
            }
        }
        false
    }

    fn has_liquidation_bypass_via_yield(&self) -> bool {
        // Pattern: liquidation check that can be bypassed with yield
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for collateral ratio check
            if self.bytecode[i] == 0x04 { // DIV (ratio = collateral / debt)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for liquidation threshold check
                let checks_liquidation = window.windows(8).any(|w| {
                    w.iter().any(|&op| op == 0x10 || op == 0x11) && // LT/GT
                    w.iter().any(|&op| op == 0x57) // JUMPI (liquidation trigger)
                });
                
                // Check if debt uses yield-adjusted value
                let uses_yield_adjusted_debt = window.windows(15).any(|w| {
                    // debt - accruedYield
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Multiple SLOAD
                    w.iter().any(|&op| op == 0x03) // SUB
                });
                
                // Check for actual debt validation
                let validates_actual_debt = window.windows(10).any(|w| {
                    // Use original debt amount, not yield-adjusted
                    w.iter().any(|&op| op == 0x20) && // KECCAK256 (original debt key)
                    w.iter().any(|&op| op == 0x54) // SLOAD
                });
                
                if checks_liquidation && uses_yield_adjusted_debt && !validates_actual_debt {
                    return true;
                }
            }
        }
        false
    }

    fn has_transmuter_rate_manipulation(&self) -> bool {
        // Pattern: transmute() with manipulable exchange rate
        let transmute_selector = [0x3c, 0x64, 0xf0, 0x4e]; // transmute()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == transmute_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for exchange rate calculation
                    let calculates_rate = window.iter().any(|&op| {
                        op == 0x04 // DIV (exchange rate)
                    });
                    
                    // Check for rate bounds
                    let has_rate_bounds = window.windows(8).any(|w| {
                        // min_rate < rate < max_rate
                        w.iter().filter(|&&op| op == 0x10 || op == 0x11).count() >= 2
                    });
                    
                    // Check for TWAP
                    let uses_twap = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().filter(|&&op| op == 0x54).count() >= 2 // Historical prices
                    });
                    
                    if calculates_rate && !has_rate_bounds && !uses_twap {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_debt_share_dilution_risk(&self) -> bool {
        // Pattern: debt share calculation vulnerable to dilution
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x04 { // DIV (share calculation)
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check for share-based debt accounting
                let uses_shares = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0x02) && // MUL
                    w.iter().any(|&op| op == 0x04) && // DIV (shares formula)
                    w.iter().any(|&op| op == 0x18) // TOTALSSUPPLY
                });
                
                // Check for minimum share protection
                let has_min_share = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x11) && // GT (share > min)
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                if uses_shares && !has_min_share {
                    return true;
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
    fn test_alchemix_yield_manipulation() {
        let vulnerable_bytecode = vec![
            0x54, // SLOAD (yield)
            0x03, // SUB (debt - yield)
            0x55, // SSTORE (repay debt - no yield validation!)
        ];

        let detector = AlchemixSelfRepayingDebtDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("yield") || w.description.contains("debt")));
    }
}
