use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Alpha Homora Leveraged Yield Farming Detector
/// 
/// Detects vulnerabilities in leveraged yield farming protocols where position
/// accounting errors enable over-borrowing and collateral manipulation.
/// 
/// **Historical Exploits**: 
/// - Alpha Homora v1 ($37M, February 2021)
/// - Alpha Homora v2 (multiple attacks, 2021)
/// 
/// **Attack Patterns**:
/// 1. **Position Accounting Errors**: Borrow/collateral tracking mismatch
/// 2. **Leveraged Position Manipulation**: Recursive borrowing without limits
/// 3. **Collateral Valuation Bypass**: Price oracle manipulation in leveraged context
/// 4. **Debt Share Calculation Errors**: Share dilution attacks
/// 5. **Cross-Protocol Position Interaction**: External protocol calls corrupt position state
/// 
/// **Core Vulnerabilities**:
/// - Incorrect debt share calculations (rounding errors)
/// - Missing leverage ratio enforcement
/// - Collateral double-counting across protocols
/// - Reentrancy in position state updates
/// 
/// **Detection Strategy**:
/// - Identifies debt share calculation without proper rounding protection
/// - Detects missing leverage ratio limits
/// - Flags position updates without reentrancy guards
/// - Checks for collateral valuation in external protocol calls
/// - Validates debt accounting consistency
pub struct AlphaHomoraLeveragedYieldDetector {
    bytecode: Vec<u8>,
}

impl AlphaHomoraLeveragedYieldDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_debt_share_rounding_error() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Debt share calculation vulnerable to rounding errors - Alpha Homora vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use precise math for debt share calculations with rounding protection".to_string(),
            });
        }

        if self.has_missing_leverage_ratio_limit() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "No maximum leverage ratio enforcement - enables excessive borrowing".to_string(),
                operations: Vec::new(),
                remediation: "Implement strict maximum leverage ratio (e.g., 3x-5x) with validation before borrow".to_string(),
            });
        }

        if self.has_position_state_reentrancy() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Position state updates vulnerable to reentrancy during external calls".to_string(),
                operations: Vec::new(),
                remediation: "Add reentrancy guards before all position state-changing operations".to_string(),
            });
        }

        if self.has_collateral_double_counting() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Collateral can be counted multiple times across protocol interactions".to_string(),
                operations: Vec::new(),
                remediation: "Track collateral usage per position to prevent double-counting".to_string(),
            });
        }

        if self.has_unsafe_external_protocol_call() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "External protocol calls can corrupt position accounting".to_string(),
                operations: Vec::new(),
                remediation: "Validate position state before and after external protocol interactions".to_string(),
            });
        }

        warnings
    }

    fn has_debt_share_rounding_error(&self) -> bool {
        // Pattern: debtShare = debt * totalShare / totalDebt (vulnerable to rounding)
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x04 { // DIV (share calculation)
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check for debt share calculation pattern
                let has_share_calc = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x02) && // MUL (debt * totalShare)
                    w.iter().any(|&op| op == 0x04) // DIV (/ totalDebt)
                });
                
                // Check for rounding protection
                let has_rounding_protection = window.windows(8).any(|w| {
                    // Pattern: adding 1 before division or using SafeMath
                    w.iter().any(|&op| op == 0x01) && // ADD (rounding adjustment)
                    w.iter().any(|&op| op == 0x60 && w[1] == 0x01) // PUSH1 0x01
                });
                
                // Check for minimum share enforcement
                let has_min_share = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x11) && // GT (share > minimum)
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                // Check for SafeMath library usage
                let uses_safe_math = window.iter().any(|&op| {
                    op == 0xfa // STATICCALL (to SafeMath)
                });
                
                if has_share_calc && !has_rounding_protection && !has_min_share && !uses_safe_math {
                    return true;
                }
            }
        }
        false
    }

    fn has_missing_leverage_ratio_limit(&self) -> bool {
        // Pattern: borrow() without leverage ratio check
        let borrow_selector = [0xc5, 0xea, 0xbe, 0xec]; // borrow()
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == borrow_selector {
                    let window = &self.bytecode[i..i+70.min(self.bytecode.len())];
                    
                    // Check for borrow amount update
                    let has_borrow_update = window.windows(5).any(|w| {
                        w.iter().any(|&op| op == 0x01) && // ADD (increase debt)
                        w.iter().any(|&op| op == 0x55) // SSTORE
                    });
                    
                    // Check for leverage ratio calculation
                    let has_leverage_calc = window.windows(15).any(|w| {
                        // Pattern: totalBorrow / totalCollateral
                        w.iter().any(|&op| op == 0x54) && // SLOAD (collateral)
                        w.iter().any(|&op| op == 0x04) && // DIV (debt/collateral)
                        w.iter().any(|&op| op == 0x10 || op == 0x11) // LT/GT (ratio check)
                    });
                    
                    // Check for maximum leverage limit
                    let has_max_leverage = window.windows(8).any(|w| {
                        // Pattern: ratio < maxLeverage
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max ratio)
                        w.iter().any(|&op| op == 0x10) && // LT
                        w.iter().any(|&op| op == 0xfd) // REVERT if exceeded
                    });
                    
                    if has_borrow_update && !has_leverage_calc && !has_max_leverage {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_position_state_reentrancy(&self) -> bool {
        // Pattern: external call followed by position state update
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL or STATICCALL
                let window_after = &self.bytecode[i..i+50.min(self.bytecode.len())];
                let window_before = &self.bytecode[i.saturating_sub(30)..i];
                
                // Check if this is a position-related call
                let has_position_update_after = window_after.windows(10).any(|w| {
                    // Pattern: updating position state after external call
                    w.iter().filter(|&&op| op == 0x55).count() >= 2 // Multiple SSTORE
                });
                
                // Check for reentrancy guard
                let has_reentrancy_guard = window_before.windows(8).any(|w| {
                    // Pattern: SLOAD(guard) -> ISZERO -> SSTORE(lock)
                    w.iter().any(|&op| op == 0x54) && // SLOAD
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().filter(|&&op| op == 0x55).count() >= 1 // SSTORE (set lock)
                });
                
                // Check for checks-effects-interactions pattern
                let follows_cei = window_before.windows(15).any(|w| {
                    // State updates before external call
                    w.iter().filter(|&&op| op == 0x55).count() >= 2
                });
                
                if has_position_update_after && !has_reentrancy_guard && !follows_cei {
                    return true;
                }
            }
        }
        false
    }

    fn has_collateral_double_counting(&self) -> bool {
        // Pattern: collateral read multiple times without tracking usage
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for collateral balance checks
            if self.bytecode[i] == 0x31 || self.bytecode[i] == 0xfa { // BALANCE or STATICCALL
                let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                
                // Check for multiple collateral reads
                let multiple_collateral_reads = window.iter().filter(|&&op| {
                    op == 0x31 || op == 0xfa // Multiple balance checks
                }).count() >= 2;
                
                // Check for collateral usage tracking
                let tracks_usage = window.windows(12).any(|w| {
                    // Pattern: usedCollateral + newAmount -> SSTORE
                    w.iter().any(|&op| op == 0x54) && // SLOAD (used amount)
                    w.iter().any(|&op| op == 0x01) && // ADD (track usage)
                    w.iter().any(|&op| op == 0x55) // SSTORE (update tracking)
                });
                
                // Check for position-specific collateral accounting
                let has_position_accounting = window.windows(10).any(|w| {
                    // Pattern: KECCAK256(positionId) for unique tracking
                    w.iter().any(|&op| op == 0x20) && // KECCAK256
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 // Multiple SLOAD
                });
                
                if multiple_collateral_reads && !tracks_usage && !has_position_accounting {
                    return true;
                }
            }
        }
        false
    }

    fn has_unsafe_external_protocol_call(&self) -> bool {
        // Pattern: external protocol interaction without state validation
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0xf1 { // CALL (to external protocol)
                let window = &self.bytecode[i.saturating_sub(40)..i+15.min(self.bytecode.len())];
                
                // Check if target is external protocol
                let is_external_protocol = window.iter().any(|&op| {
                    op == 0x54 || op == 0x35 // SLOAD or CALLDATALOAD (dynamic target)
                });
                
                // Check for pre-call state snapshot
                let has_pre_snapshot = window.windows(15).any(|w| {
                    // Save position state before call
                    w.iter().filter(|&&op| op == 0x54).count() >= 3 // Multiple SLOAD (read state)
                });
                
                // Check for post-call validation
                let has_post_validation = self.bytecode[i..i+55.min(self.bytecode.len())].windows(15).any(|w| {
                    // Validate position consistency after call
                    w.iter().any(|&op| op == 0x54) && // SLOAD (check state)
                    w.iter().any(|&op| op == 0x14 || op == 0x10 || op == 0x11) && // Compare
                    w.iter().any(|&op| op == 0xfd) // REVERT if inconsistent
                });
                
                // Check for return value validation
                let validates_return = self.bytecode[i..i+15.min(self.bytecode.len())].windows(5).any(|w| {
                    w.iter().any(|&op| op == 0x15) && // ISZERO (check success)
                    w.iter().any(|&op| op == 0xfd) // REVERT on failure
                });
                
                if is_external_protocol && !has_pre_snapshot && !has_post_validation && !validates_return {
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
    fn test_alpha_homora_debt_share_rounding() {
        let vulnerable_bytecode = vec![
            0x02, // MUL (debt * totalShare)
            0x04, // DIV (/ totalDebt - vulnerable to rounding!)
            0x55, // SSTORE (store share without rounding protection)
        ];

        let detector = AlphaHomoraLeveragedYieldDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("share") || w.description.contains("rounding")));
    }

    #[test]
    fn test_missing_leverage_limit() {
        let vulnerable_bytecode = vec![
            0x63, 0xc5, 0xea, 0xbe, 0xec, // borrow()
            0x01, // ADD (increase debt)
            0x55, // SSTORE (no leverage ratio check!)
        ];

        let detector = AlphaHomoraLeveragedYieldDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| w.description.contains("leverage")));
    }
}
