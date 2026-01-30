/// Lending Collateral Invariant Validator
/// Verifies lending protocols maintain collateralization ratios
/// Critical for: Aave, Compound, MakerDAO, all CDP/lending systems

use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct LendingCollateralInvariantValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CollateralViolation {
    pub location: usize,
    pub violation_type: CollateralViolationType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CollateralViolationType {
    BorrowWithoutCollateralCheck,     // Borrow without checking health factor
    LiquidationBelowThreshold,         // Liquidation when still healthy
    CollateralNotLockedAtomically,     // Collateral released before debt paid
    HealthFactorNotRecalculated,       // HF not updated after price change
    LTVExceedsMaximum,                 // Loan-to-value ratio too high
    MultiCollateralSumError,           // Total collateral miscalculated
}

impl LendingCollateralInvariantValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate(&self) -> Vec<CollateralViolation> {
        let mut violations = Vec::new();

        violations.extend(self.check_borrow_collateral_verification());
        violations.extend(self.check_liquidation_threshold());
        violations.extend(self.check_collateral_atomicity());
        violations.extend(self.check_health_factor_updates());

        violations
    }

    fn check_borrow_collateral_verification(&self) -> Vec<CollateralViolation> {
        let mut violations = Vec::new();
        
        // Pattern: Borrow must check: collateral * price * LTV >= debt
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.has_borrow_operation(i) {
                if !self.has_health_factor_check(i, 80) {
                    violations.push(CollateralViolation {
                        location: i,
                        violation_type: CollateralViolationType::BorrowWithoutCollateralCheck,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.88,
                        description: format!(
                            "Borrow at PC {} doesn't verify health factor. \
                            Under-collateralized loans possible.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_liquidation_threshold(&self) -> Vec<CollateralViolation> {
        let mut violations = Vec::new();

        // Pattern: Liquidation should only occur if HF < 1.0
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.has_liquidation_operation(i) {
                if !self.has_threshold_check_before(i, 30) {
                    violations.push(CollateralViolation {
                        location: i,
                        violation_type: CollateralViolationType::LiquidationBelowThreshold,
                        severity: SecuritySeverity::High,
                        confidence: 0.82,
                        description: format!(
                            "Liquidation at PC {} may execute above threshold. \
                            Healthy positions can be liquidated.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_collateral_atomicity(&self) -> Vec<CollateralViolation> {
        let mut violations = Vec::new();

        // Pattern: Collateral release must be after debt payment
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.has_collateral_release(i) {
                if !self.has_debt_payment_before(i, 50) {
                    violations.push(CollateralViolation {
                        location: i,
                        violation_type: CollateralViolationType::CollateralNotLockedAtomically,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: format!(
                            "Collateral release at PC {} before debt check. \
                            Reentrancy could steal collateral.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_health_factor_updates(&self) -> Vec<CollateralViolation> {
        let mut violations = Vec::new();

        // Pattern: After any operation affecting debt/collateral, HF must be recalculated
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.has_state_changing_operation(i) {
                if !self.has_health_factor_recalc(i, 100) {
                    violations.push(CollateralViolation {
                        location: i,
                        violation_type: CollateralViolationType::HealthFactorNotRecalculated,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "State change at PC {} doesn't recalculate health factor. \
                            Stale HF could allow under-collateralized borrows.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    // Helper detection methods
    
    fn has_borrow_operation(&self, pc: usize) -> bool {
        // Borrow pattern: increase debt, transfer tokens
        let window = self.bytecode.get(pc..pc.saturating_add(30)).unwrap_or(&[]);
        window.contains(&0x55) && window.contains(&0xf1) // SSTORE and CALL
    }

    fn has_health_factor_check(&self, pc: usize, range: usize) -> bool {
        // Look for: collateral * price * ltv / debt > threshold
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        let mul_count = window.iter().filter(|&&b| b == 0x02).count();
        let div_count = window.iter().filter(|&&b| b == 0x04).count();
        let has_comparison = window.contains(&0x10) || window.contains(&0x11);
        
        mul_count >= 2 && div_count >= 1 && has_comparison
    }

    fn has_liquidation_operation(&self, pc: usize) -> bool {
        // Liquidation: transfer collateral, reduce debt
        let window = self.bytecode.get(pc..pc.saturating_add(25)).unwrap_or(&[]);
        window.contains(&0xf1) && window.contains(&0x55) // CALL and SSTORE
    }

    fn has_threshold_check_before(&self, pc: usize, range: usize) -> bool {
        // Check for comparison before liquidation
        if pc < range { return false; }
        let window = self.bytecode.get(pc.saturating_sub(range)..pc).unwrap_or(&[]);
        window.contains(&0x10) || window.contains(&0x11) // LT or GT
    }

    fn has_collateral_release(&self, pc: usize) -> bool {
        // Pattern: Transfer token out (CALL with value)
        self.bytecode.get(pc) == Some(&0xf1) // CALL
    }

    fn has_debt_payment_before(&self, pc: usize, range: usize) -> bool {
        if pc < range { return false; }
        let window = self.bytecode.get(pc.saturating_sub(range)..pc).unwrap_or(&[]);
        // Look for SSTORE (debt update) before collateral release
        window.contains(&0x55)
    }

    fn has_state_changing_operation(&self, pc: usize) -> bool {
        // Any SSTORE affecting balances
        self.bytecode.get(pc) == Some(&0x55)
    }

    fn has_health_factor_recalc(&self, pc: usize, range: usize) -> bool {
        // Look for complex calculation after state change
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        let mul_count = window.iter().filter(|&&b| b == 0x02).count();
        let div_count = window.iter().filter(|&&b| b == 0x04).count();
        mul_count >= 2 && div_count >= 1
    }
}
