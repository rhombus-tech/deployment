/// AMM Constant Product Invariant Validator
/// Verifies that AMM pools correctly maintain the k = x * y invariant
/// 
/// Critical for: Uniswap V2, SushiSwap, PancakeSwap, and all xy=k AMMs
/// Prevents: Incorrect swap pricing, arbitrage drain, liquidity theft

use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct AMMConstantProductInvariantValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConstantProductViolation {
    pub location: usize,
    pub violation_type: InvariantViolationType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InvariantViolationType {
    KNotMaintainedAfterSwap,      // k decreases after swap (theft)
    ReservesNotUpdatedAtomically,  // Reserve update race condition
    FeeNotAppliedBeforeK,          // Fee calculation breaks invariant
    IntegerOverflowInK,            // k * 1000 overflows
    ReserveRatioManipulated,       // Reserves changed without swap
    MinLiquidityNotEnforced,       // No minimum liquidity protection
    BurnCalculationError,          // LP token burn doesn't match reserves
    MintCalculationError,          // LP token mint doesn't match reserves
}

impl AMMConstantProductInvariantValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate(&self) -> Vec<ConstantProductViolation> {
        let mut violations = Vec::new();

        // Check for swap function patterns
        violations.extend(self.check_swap_k_maintenance());
        violations.extend(self.check_reserve_atomicity());
        violations.extend(self.check_fee_application());
        violations.extend(self.check_k_overflow_protection());
        violations.extend(self.check_mint_burn_correctness());

        violations
    }

    fn check_swap_k_maintenance(&self) -> Vec<ConstantProductViolation> {
        let mut violations = Vec::new();
        
        // Pattern: Look for swap implementations
        // 1. Load reserve0 and reserve1
        // 2. Calculate amountOut
        // 3. Update reserves
        // 4. CHECK: k_after >= k_before (with fee consideration)
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for swap-like pattern: multiple SLOADs followed by arithmetic
            if self.has_dual_reserve_load(i) {
                // Check if k is recalculated and verified
                if !self.has_k_verification_after_swap(i, 100) {
                    violations.push(ConstantProductViolation {
                        location: i,
                        violation_type: InvariantViolationType::KNotMaintainedAfterSwap,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.82,
                        description: format!(
                            "Swap at PC {} does not verify k invariant. \
                            Attacker could drain pool by manipulating reserves.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_reserve_atomicity(&self) -> Vec<ConstantProductViolation> {
        let mut violations = Vec::new();

        // Pattern: Reserve updates must be atomic (no external calls between update and sync)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_reserve_update(i) {
                // Check for external call before sync
                if self.has_external_call_before_sync(i, 50) {
                    violations.push(ConstantProductViolation {
                        location: i,
                        violation_type: InvariantViolationType::ReservesNotUpdatedAtomically,
                        severity: SecuritySeverity::High,
                        confidence: 0.78,
                        description: format!(
                            "Reserve update at PC {} has external call before sync. \
                            Reentrancy could violate invariant.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_fee_application(&self) -> Vec<ConstantProductViolation> {
        let mut violations = Vec::new();

        // Pattern: Fee must be applied BEFORE calculating output amount
        // Correct: amountOut = (reserve1 * amountIn * 997) / (reserve0 * 1000 + amountIn * 997)
        // Wrong: amountOut = ... then subtract fee
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.has_swap_calculation(i) {
                if !self.has_fee_in_numerator(i, 30) {
                    violations.push(ConstantProductViolation {
                        location: i,
                        violation_type: InvariantViolationType::FeeNotAppliedBeforeK,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Swap at PC {} applies fee after calculation. \
                            k invariant violated, enables arbitrage.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_k_overflow_protection(&self) -> Vec<ConstantProductViolation> {
        let mut violations = Vec::new();

        // Pattern: k = reserve0 * reserve1 must check for overflow
        // Especially: k * 1000 (for fee calculation) can overflow
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_k_calculation(i) {
                if !self.has_overflow_check(i, 15) && !self.uses_safe_math(i, 15) {
                    violations.push(ConstantProductViolation {
                        location: i,
                        violation_type: InvariantViolationType::IntegerOverflowInK,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "K calculation at PC {} lacks overflow protection. \
                            Integer overflow could break invariant completely.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    fn check_mint_burn_correctness(&self) -> Vec<ConstantProductViolation> {
        let mut violations = Vec::new();

        // Pattern: LP token mint/burn must match reserve changes
        // Mint: liquidity = min(amount0 * totalSupply / reserve0, amount1 * totalSupply / reserve1)
        // Burn: amount0 = liquidity * reserve0 / totalSupply (same for amount1)

        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Check mint operations
            if self.has_mint_pattern(i) {
                if !self.has_minimum_check(i, 50) {
                    violations.push(ConstantProductViolation {
                        location: i,
                        violation_type: InvariantViolationType::MintCalculationError,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: format!(
                            "Mint at PC {} doesn't use minimum of both ratios. \
                            Enables liquidity theft via imbalanced deposits.",
                            i
                        ),
                    });
                }
            }

            // Check burn operations
            if self.has_burn_pattern(i) {
                if !self.has_proportional_withdrawal(i, 50) {
                    violations.push(ConstantProductViolation {
                        location: i,
                        violation_type: InvariantViolationType::BurnCalculationError,
                        severity: SecuritySeverity::High,
                        confidence: 0.77,
                        description: format!(
                            "Burn at PC {} doesn't maintain proportional withdrawal. \
                            LP holders can be shortchanged.",
                            i
                        ),
                    });
                }
            }
        }

        violations
    }

    // Helper methods for pattern matching
    
    fn has_dual_reserve_load(&self, pc: usize) -> bool {
        // Look for pattern: SLOAD(slot0), SLOAD(slot1)
        let window = self.bytecode.get(pc..pc.saturating_add(20)).unwrap_or(&[]);
        let sload_count = window.iter().filter(|&&b| b == 0x54).count(); // SLOAD
        sload_count >= 2
    }

    fn has_k_verification_after_swap(&self, pc: usize, range: usize) -> bool {
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        // Look for MUL followed by comparison (GT or LT)
        for i in 0..window.len().saturating_sub(3) {
            if window[i] == 0x02 { // MUL
                if window.get(i+1..i+4).map_or(false, |w| w.contains(&0x10) || w.contains(&0x11)) {
                    // Found MUL followed by LT(0x10) or GT(0x11)
                    return true;
                }
            }
        }
        false
    }

    fn has_reserve_update(&self, pc: usize) -> bool {
        // SSTORE pattern
        self.bytecode.get(pc) == Some(&0x55)
    }

    fn has_external_call_before_sync(&self, pc: usize, range: usize) -> bool {
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        // Look for CALL (0xf1) or DELEGATECALL (0xf4) before next SSTORE
        for (i, &byte) in window.iter().enumerate() {
            if byte == 0x55 { // SSTORE (sync)
                return false; // Found sync first, no problem
            }
            if byte == 0xf1 || byte == 0xf4 { // CALL or DELEGATECALL
                return true; // Found external call before sync
            }
        }
        false
    }

    fn has_swap_calculation(&self, pc: usize) -> bool {
        // Look for multiplication and division pattern (typical in swap math)
        let window = self.bytecode.get(pc..pc.saturating_add(20)).unwrap_or(&[]);
        window.contains(&0x02) && window.contains(&0x04) // MUL and DIV
    }

    fn has_fee_in_numerator(&self, pc: usize, range: usize) -> bool {
        // Look for pattern: amountIn * 997 (or 9970, etc.)
        // This is indicated by PUSH(997/9970) followed by MUL
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        for i in 0..window.len().saturating_sub(4) {
            if window[i] == 0x61 { // PUSH2
                // Check if next bytes are 997 (0x03E5) or 9970 (0x26F2)
                let value = u16::from_be_bytes([window.get(i+1).copied().unwrap_or(0), 
                                                 window.get(i+2).copied().unwrap_or(0)]);
                if value == 997 || value == 9970 || value == 9975 {
                    // Check for MUL nearby
                    if window.get(i+3..i+6).map_or(false, |w| w.contains(&0x02)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_k_calculation(&self, pc: usize) -> bool {
        // reserve0 * reserve1 pattern
        let window = self.bytecode.get(pc..pc.saturating_add(15)).unwrap_or(&[]);
        // Two SLOADs followed by MUL
        let mut sload_positions = Vec::new();
        for (i, &byte) in window.iter().enumerate() {
            if byte == 0x54 { sload_positions.push(i); }
        }
        if sload_positions.len() >= 2 {
            // Check for MUL after second SLOAD
            let mul_pos = window.iter().position(|&b| b == 0x02);
            return mul_pos.map_or(false, |pos| pos > sload_positions[1]);
        }
        false
    }

    fn has_overflow_check(&self, pc: usize, range: usize) -> bool {
        // Look for comparison after multiplication
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        for i in 0..window.len().saturating_sub(2) {
            if window[i] == 0x02 { // MUL
                // Check for comparison within next few opcodes
                if window.get(i+1..i+5).map_or(false, |w| 
                    w.contains(&0x10) || w.contains(&0x11) || w.contains(&0x12)) {
                    return true;
                }
            }
        }
        false
    }

    fn uses_safe_math(&self, pc: usize, range: usize) -> bool {
        // SafeMath libraries use JUMPI after arithmetic
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        window.contains(&0x57) // JUMPI (revert on overflow)
    }

    fn has_mint_pattern(&self, pc: usize) -> bool {
        // Look for pattern that suggests LP token minting
        let window = self.bytecode.get(pc..pc.saturating_add(30)).unwrap_or(&[]);
        // Mint typically: load totalSupply, DIV, MUL pattern
        window.contains(&0x04) && window.contains(&0x02) // DIV and MUL
    }

    fn has_minimum_check(&self, pc: usize, range: usize) -> bool {
        // Look for MIN function: DUP, DUP, LT, JUMPI pattern
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        for i in 0..window.len().saturating_sub(4) {
            if window[i] == 0x80 && window[i+1] == 0x81 { // DUP1, DUP2
                if window.get(i+2..i+5).map_or(false, |w| w.contains(&0x10)) { // LT
                    return true;
                }
            }
        }
        false
    }

    fn has_burn_pattern(&self, pc: usize) -> bool {
        // Look for LP token burning pattern
        let window = self.bytecode.get(pc..pc.saturating_add(30)).unwrap_or(&[]);
        // Burn typically involves: MUL reserve, DIV totalSupply
        window.contains(&0x02) && window.contains(&0x04)
    }

    fn has_proportional_withdrawal(&self, pc: usize, range: usize) -> bool {
        // Both token amounts must be calculated the same way
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        let div_count = window.iter().filter(|&&b| b == 0x04).count();
        div_count >= 2 // Both amounts divided by totalSupply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_missing_k_verification() {
        // Bytecode pattern: swap without k check
        let bytecode = vec![
            0x54, // SLOAD (reserve0)
            0x54, // SLOAD (reserve1)
            0x02, // MUL
            0x04, // DIV (calculate output)
            0x55, // SSTORE (update reserve)
            // Missing: k verification
        ];

        let validator = AMMConstantProductInvariantValidator::new(bytecode);
        let violations = validator.validate();
        
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| 
            matches!(v.violation_type, InvariantViolationType::KNotMaintainedAfterSwap)
        ));
    }

    #[test]
    fn test_detects_reentrancy_before_sync() {
        let bytecode = vec![
            0x55, // SSTORE (reserve update)
            0xf1, // CALL (external call before sync!)
            0x55, // SSTORE (sync)
        ];

        let validator = AMMConstantProductInvariantValidator::new(bytecode);
        let violations = validator.validate();
        
        assert!(violations.iter().any(|v| 
            matches!(v.violation_type, InvariantViolationType::ReservesNotUpdatedAtomically)
        ));
    }

    #[test]
    fn test_detects_incorrect_fee_application() {
        // Fee applied after calculation (wrong)
        let bytecode = vec![
            0x02, // MUL
            0x04, // DIV (calculate output)
            0x60, 0x03, // PUSH 3 (fee)
            0x03, // SUB (subtract fee after - WRONG!)
        ];

        let validator = AMMConstantProductInvariantValidator::new(bytecode);
        let violations = validator.check_fee_application();
        
        assert!(!violations.is_empty());
    }
}
