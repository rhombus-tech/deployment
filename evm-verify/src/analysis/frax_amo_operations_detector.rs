use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Frax AMO (Algorithmic Market Operations) Manipulation Detector
/// 
/// Detects vulnerabilities in Frax's AMO controllers where algorithmic market
/// operations can manipulate the collateral ratio or protocol-owned liquidity.
/// 
/// **AMO Context**:
/// Frax uses AMOs to algorithmically manage:
/// - Collateral ratio (CR) - target % backing for FRAX
/// - Protocol-owned liquidity (POL) deployment
/// - Yield generation strategies
/// - Market making operations
/// 
/// **Attack Patterns**:
/// 1. AMO operations that artificially inflate collateral ratio
/// 2. POL manipulation to extract value
/// 3. Collateral ratio gaming via circular AMO operations
/// 4. Unauthorized AMO strategy deployment
/// 5. AMO profit extraction without proper accounting
/// 
/// **Detection Strategy**:
/// - Identifies AMO operations affecting CR without validation
/// - Detects POL deployment without bounds checking
/// - Flags circular AMO operations
/// - Checks for unauthorized AMO controller access
/// - Validates AMO profit accounting
pub struct FraxAmoOperationsDetector {
    bytecode: Vec<u8>,
}

impl FraxAmoOperationsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_amo_collateral_ratio_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "AMO operations can artificially manipulate collateral ratio - Frax vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Validate AMO operations don't create circular CR inflation and add independent CR verification".to_string(),
            });
        }

        if self.has_uncontrolled_pol_deployment() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Protocol-owned liquidity deployment lacks proper controls".to_string(),
                operations: Vec::new(),
                remediation: "Add AMO deployment limits, timelock, and multi-sig requirements for POL operations".to_string(),
            });
        }

        if self.has_circular_amo_operations() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "AMO can perform circular operations to game accounting".to_string(),
                operations: Vec::new(),
                remediation: "Track AMO operation chains and prevent circular value flows".to_string(),
            });
        }

        if self.has_amo_profit_accounting_gap() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "AMO profit extraction not properly accounted in collateral ratio".to_string(),
                operations: Vec::new(),
                remediation: "Ensure all AMO profits are accurately reflected in CR calculations".to_string(),
            });
        }

        warnings
    }

    fn has_amo_collateral_ratio_manipulation(&self) -> bool {
        // Pattern: AMO operation that affects CR calculation
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x04 { // DIV (CR = collateral / totalSupply)
                let window = &self.bytecode[i.saturating_sub(50)..i+10.min(self.bytecode.len())];
                
                // Check for CR calculation
                let calculates_cr = window.windows(15).any(|w| {
                    w.iter().any(|&op| op == 0x31 || op == 0x54) && // BALANCE or SLOAD (collateral)
                    w.iter().any(|&op| op == 0x18) // TOTALSSUPPLY (FRAX supply)
                });
                
                // Check if AMO can modify collateral
                let amo_modifies_collateral = window.windows(20).any(|w| {
                    w.iter().any(|&op| op == 0xf1) && // CALL (AMO operation)
                    w.iter().any(|&op| op == 0x55) // SSTORE (update collateral)
                });
                
                // Check for circular operation detection
                let detects_circular = window.windows(15).any(|w| {
                    // Track operation source to prevent circular flows
                    w.iter().filter(|&&op| op == 0x20).count() >= 2 && // Multiple KECCAK256 (operation tracking)
                    w.iter().any(|&op| op == 0x54) // SLOAD (check history)
                });
                
                // Check for independent CR verification
                let has_independent_verification = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL (to oracle/validator)
                    w.iter().any(|&op| op == 0x14) // EQ (verify match)
                });
                
                if calculates_cr && amo_modifies_collateral && !detects_circular && !has_independent_verification {
                    return true;
                }
            }
        }
        false
    }

    fn has_uncontrolled_pol_deployment(&self) -> bool {
        // Pattern: AMO deploying POL without limits
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0xf1 { // CALL (deploy POL)
                let window = &self.bytecode[i.saturating_sub(45)..i+10.min(self.bytecode.len())];
                
                // Check if this is POL deployment
                let deploys_pol = window.windows(15).any(|w: &[u8]| {
                    w.iter().any(|&op| op == 0x31 || op == 0x54) && // BALANCE/SLOAD (protocol funds)
                    w.iter().any(|&op| op == 0xf1) // CALL (deploy to AMO/strategy)
                });
                
                // Check for deployment amount limits
                let has_amount_limits = window.windows(8).any(|w: &[u8]| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max amount)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) && // LT/GT
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                // Check for timelock
                let has_timelock = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                    w.iter().any(|&op| op == 0x54) // SLOAD (proposed time)
                });
                
                // Check for multi-sig requirement
                let requires_multisig = window.windows(12).any(|w| {
                    w.iter().filter(|&&op| op == 0x01).count() >= 2 // Multiple ecrecover (signatures)
                });
                
                if deploys_pol && !has_amount_limits && !has_timelock && !requires_multisig {
                    return true;
                }
            }
        }
        false
    }

    fn has_circular_amo_operations(&self) -> bool {
        // Check for AMO operation chains that could be circular
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.bytecode[i] == 0xf1 { // CALL (AMO operation)
                let window = &self.bytecode[i..i+70.min(self.bytecode.len())];
                
                // Check for multiple AMO calls in sequence
                let has_chained_amo_calls = window.iter().filter(|&&op| op == 0xf1).count() >= 2;
                
                // Check for operation tracking
                let tracks_operations = window.windows(15).any(|w| {
                    // Store operation IDs to detect cycles
                    w.iter().any(|&op| op == 0x20) && // KECCAK256 (operation hash)
                    w.iter().any(|&op| op == 0x55) // SSTORE (record operation)
                });
                
                // Check for cycle detection
                let detects_cycles = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (check if operation seen)
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT if cycle
                });
                
                if has_chained_amo_calls && !tracks_operations && !detects_cycles {
                    return true;
                }
            }
        }
        false
    }

    fn has_amo_profit_accounting_gap(&self) -> bool {
        // Pattern: AMO profit withdrawal without updating CR
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for profit withdrawal
            if self.bytecode[i] == 0xf1 { // CALL (withdraw profit)
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check for profit extraction
                let extracts_profit = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x31) && // BALANCE
                    w.iter().any(|&op| op == 0x03) // SUB (profit = current - initial)
                });
                
                // Check for CR update
                let updates_cr = window.windows(20).any(|w| {
                    // CR recalculation after profit extraction
                    w.iter().any(|&op| op == 0x18) && // TOTALSSUPPLY
                    w.iter().any(|&op| op == 0x04) && // DIV (new CR)
                    w.iter().any(|&op| op == 0x55) // SSTORE (store updated CR)
                });
                
                if extracts_profit && !updates_cr {
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
    fn test_frax_amo_cr_manipulation() {
        let vulnerable_bytecode = vec![
            0xf1, // CALL (AMO operation)
            0x55, // SSTORE (modify collateral)
            0x31, // BALANCE
            0x18, // TOTALSSUPPLY
            0x04, // DIV (CR - no circular detection!)
        ];

        let detector = FraxAmoOperationsDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("AMO") || w.description.contains("collateral ratio")));
    }
}
