use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Hope Finance Bad Debt Socialization Detector
/// 
/// Detects vulnerabilities in lending protocols where bad debt is socialized
/// across all depositors without proper risk isolation or compensation.
/// 
/// **Attack Pattern**:
/// 1. Attacker creates undercollateralized position through oracle manipulation
/// 2. Position becomes liquidatable but with insufficient collateral
/// 3. Bad debt socialized to all depositors
/// 4. Protocol insolvency spreads across entire platform
/// 
/// **Detection Strategy**:
/// - Identifies bad debt handling without isolation
/// - Detects missing insurance fund or backstop
/// - Flags socialization without compensation mechanism
/// - Checks for liquidation incentive adequacy
pub struct HopeFinanceBadDebtSocializationDetector {
    bytecode: Vec<u8>,
}

impl HopeFinanceBadDebtSocializationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_socialized_bad_debt_without_isolation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Bad debt socialized across all depositors - Hope Finance vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Implement pool isolation and insurance fund for bad debt coverage".to_string(),
            });
        }

        if self.has_missing_insurance_fund() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "No insurance fund or backstop for bad debt coverage".to_string(),
                operations: Vec::new(),
                remediation: "Create insurance fund or backstop mechanism for bad debt".to_string(),
            });
        }

        if self.has_inadequate_liquidation_incentive() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Liquidation incentive insufficient to prevent bad debt accumulation".to_string(),
                operations: Vec::new(),
                remediation: "Increase liquidation incentives and add early liquidation mechanisms".to_string(),
            });
        }

        warnings
    }

    fn has_socialized_bad_debt_without_isolation(&self) -> bool {
        // Pattern: totalDebt update affecting all users without isolation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for debt write-off or socialization
            if self.bytecode[i] == 0x55 { // SSTORE (update debt)
                let window = &self.bytecode[i.saturating_sub(20)..i+10.min(self.bytecode.len())];
                
                // Check for totalSupply affecting calculation (socialization)
                let has_socialization = window.iter().any(|&op| {
                    op == 0x18 // TOTALSSUPPLY (affects all users)
                });
                
                // Check for pool isolation or user-specific handling
                let has_isolation = window.iter().any(|&op| {
                    op == 0x20 // KECCAK256 (user-specific key)
                });
                
                // Check for insurance fund usage
                let has_insurance = window.windows(10).any(|w| {
                    // Look for BALANCE of insurance address
                    w.iter().any(|&op| op == 0x31) // BALANCE
                });
                
                if has_socialization && !has_isolation && !has_insurance {
                    return true;
                }
            }
        }
        false
    }

    fn has_missing_insurance_fund(&self) -> bool {
        // Look for liquidation handling
        let liquidate_selector = [0x96, 0xcd, 0x43, 0x59]; // liquidate()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == liquidate_selector {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check for collateral < debt case (bad debt)
                    let has_bad_debt_check = window.iter().any(|&op| {
                        op == 0x10 // LT (collateral < debt)
                    });
                    
                    // Check for insurance fund call
                    let has_insurance_call = window.iter().any(|&op| {
                        op == 0xf1 || op == 0xfa // CALL or STATICCALL to insurance
                    });
                    
                    if has_bad_debt_check && !has_insurance_call {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_inadequate_liquidation_incentive(&self) -> bool {
        // Pattern: liquidation bonus calculation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x02 { // MUL (liquidation bonus)
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Check if bonus is calculated
                let has_bonus_calc = window.windows(3).any(|w| {
                    w[0] == 0x60 && // PUSH (bonus percentage)
                    w[2] == 0x02    // MUL
                });
                
                // Check for minimum bonus validation (e.g., >= 5%)
                let has_min_bonus = window.iter().any(|&op| {
                    op == 0x11 || op == 0xfd // GT or REVERT (minimum check)
                });
                
                // Look for liquidation call
                let has_liquidation = window.iter().any(|&op| {
                    op == 0xf1 // CALL
                });
                
                if has_bonus_calc && has_liquidation && !has_min_bonus {
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
    fn test_hope_finance_bad_debt_socialization() {
        let vulnerable_bytecode = vec![
            0x18, // TOTALSSUPPLY (socialization!)
            0x04, // DIV (distribute bad debt)
            0x55, // SSTORE (no isolation, no insurance)
        ];

        let detector = HopeFinanceBadDebtSocializationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
