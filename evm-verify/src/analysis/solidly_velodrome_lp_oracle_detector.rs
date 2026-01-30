use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Solidly/Velodrome Fork LP Oracle Manipulation Detector
/// 
/// Detects vulnerabilities in Solidly/Velodrome fork LP token oracle pricing where
/// manipulated reserves can affect oracle price calculations.
/// 
/// **Historical Exploit**: Multiple Solidly/Velodrome forks
/// **Attack Pattern**:
/// 1. Attacker manipulates LP token reserves via flash loan
/// 2. Oracle reads manipulated reserve ratios for pricing
/// 3. Attacker exploits mispriced collateral/debt positions
/// 4. Profit from arbitrage and repay flash loan
/// 
/// **Detection Strategy**:
/// - Identifies getReserves() calls without TWAP protection
/// - Detects LP token price calculations using current reserves
/// - Flags missing manipulation-resistant price feeds
/// - Checks for reserve ratio validation
pub struct SolidlyVelodromeLpOracleDetector {
    bytecode: Vec<u8>,
}

impl SolidlyVelodromeLpOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        // Detection patterns for Solidly/Velodrome LP oracle issues
        if self.has_unprotected_reserve_read() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Solidly/Velodrome LP oracle: getReserves() without TWAP protection".to_string(),
                operations: Vec::new(),
                remediation: "Implement TWAP (Time-Weighted Average Price) oracle instead of spot price".to_string(),
            });
        }

        if self.has_direct_lp_pricing() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "LP token priced directly from current reserves - manipulation risk".to_string(),
                operations: Vec::new(),
                remediation: "Use fair LP pricing that accounts for reserve manipulation".to_string(),
            });
        }

        if self.has_missing_reserve_validation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Missing reserve ratio bounds checking for LP oracle".to_string(),
                operations: Vec::new(),
                remediation: "Add reserve ratio validation to detect extreme imbalances".to_string(),
            });
        }

        if self.has_sqrt_pricing_without_checks() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Square root K pricing without manipulation checks (Solidly pattern)".to_string(),
                operations: Vec::new(),
                remediation: "Add K validation and reserve bounds checks for sqrt pricing".to_string(),
            });
        }

        warnings
    }

    fn has_unprotected_reserve_read(&self) -> bool {
        // Pattern: STATICCALL to getReserves() (0x0902f1ac selector)
        // followed by price calculation without TWAP check
        for window in self.bytecode.windows(20) {
            if window[0] == 0x63 && // PUSH4
               window[1..5] == [0x09, 0x02, 0xf1, 0xac] && // getReserves()
               window.iter().skip(5).take(10).any(|&op| op == 0xfa) // STATICCALL
            {
                // Check if no observation array access (TWAP indicator)
                let has_twap = window.iter().skip(5).take(15).any(|&op| {
                    op == 0x35 || // CALLDATALOAD (observation access)
                    op == 0x54    // SLOAD (stored observations)
                });
                
                if !has_twap {
                    return true;
                }
            }
        }
        false
    }

    fn has_direct_lp_pricing(&self) -> bool {
        // Pattern: LP total supply division by reserves
        // PUSH balanceOf -> DIV -> price calculation
        let mut reserve_read = false;
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for reserve read followed by division
            if self.bytecode[i] == 0x63 && // PUSH4
               i + 5 < self.bytecode.len() &&
               self.bytecode[i+1..i+5] == [0x09, 0x02, 0xf1, 0xac] // getReserves()
            {
                reserve_read = true;
            }
            
            if reserve_read && self.bytecode[i] == 0x04 { // DIV
                // Check for totalSupply nearby
                if self.bytecode[i.saturating_sub(10)..i].iter().any(|&op| op == 0x18) { // TOTALSSUPPLY
                    return true;
                }
            }
        }
        false
    }

    fn has_missing_reserve_validation(&self) -> bool {
        // Look for reserve usage without GT/LT checks
        let mut has_reserve_load = false;
        let mut has_bounds_check = false;
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 && 
               i + 5 < self.bytecode.len() &&
               self.bytecode[i+1..i+5] == [0x09, 0x02, 0xf1, 0xac]
            {
                has_reserve_load = true;
                
                // Check next 20 bytes for comparison ops
                for j in i..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || // LT
                       self.bytecode[j] == 0x11 || // GT
                       self.bytecode[j] == 0x12    // SLT
                    {
                        has_bounds_check = true;
                        break;
                    }
                }
                
                if !has_bounds_check {
                    return true;
                }
            }
        }
        
        has_reserve_load && !has_bounds_check
    }

    fn has_sqrt_pricing_without_checks(&self) -> bool {
        // Solidly uses sqrt(k) = sqrt(reserve0 * reserve1) for pricing
        // Look for MUL followed by sqrt approximation without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 { // MUL (reserve0 * reserve1)
                // Look for DIV + EXP pattern (sqrt approximation)
                let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                let has_sqrt_approx = window.iter().enumerate().any(|(j, &op)| {
                    op == 0x04 && // DIV
                    window.get(j+1..j+3).map_or(false, |slice| {
                        slice.contains(&0x0a) // EXP (for sqrt)
                    })
                });
                
                if has_sqrt_approx {
                    // Check for validation (GT/LT check)
                    let has_validation = window.iter().any(|&op| {
                        op == 0x10 || op == 0x11 || op == 0xfd // LT, GT, REVERT
                    });
                    
                    if !has_validation {
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
    fn test_solidly_velodrome_lp_oracle_detection() {
        let vulnerable_bytecode = vec![
            0x63, 0x09, 0x02, 0xf1, 0xac, // PUSH4 getReserves()
            0x73, 0x00, 0x00, 0x00, 0x00, 0x00, // PUSH20 (pair address)
            0xfa, // STATICCALL
            0x02, // MUL (reserve0 * reserve1)
            0x04, // DIV (for pricing)
            0x55, // SSTORE (store price)
        ];

        let detector = SolidlyVelodromeLpOracleDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty(), "Should detect Solidly/Velodrome LP oracle vulnerability");
    }

    #[test]
    fn test_safe_twap_oracle() {
        let safe_bytecode = vec![
            0x63, 0x09, 0x02, 0xf1, 0xac, // PUSH4 getReserves()
            0x35, // CALLDATALOAD (observation access - TWAP)
            0x54, // SLOAD (stored observations)
            0xfa, // STATICCALL
            0x11, // GT (validation)
            0xfd, // REVERT (if invalid)
        ];

        let detector = SolidlyVelodromeLpOracleDetector::new(safe_bytecode);
        let warnings = detector.detect();
        assert!(warnings.is_empty(), "Safe TWAP oracle should not trigger warnings");
    }
}
