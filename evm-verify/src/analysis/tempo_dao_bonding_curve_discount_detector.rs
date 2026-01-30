use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// TempoDAO Bonding Curve Discount Rate Oracle Detector
/// 
/// Detects vulnerabilities in bonding curve discount rate calculations that rely on
/// manipulable oracle prices.
/// 
/// **Historical Exploit**: TempoDAO ($2.1M)
/// **Attack Pattern**:
/// 1. Attacker manipulates underlying asset price via flash loan
/// 2. Bonding curve calculates discounted price based on manipulated oracle
/// 3. Attacker purchases bonds at artificially low price
/// 4. Bonds redeemed at true value for profit
/// 
/// **Detection Strategy**:
/// - Identifies discount rate calculations using spot prices
/// - Detects missing TWAP or multi-oracle validation
/// - Flags instant price-dependent bond pricing
/// - Checks for arbitrage protection mechanisms
pub struct TempoDaoBondingCurveDiscountDetector {
    bytecode: Vec<u8>,
}

impl TempoDaoBondingCurveDiscountDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_spot_price_discount_calculation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Bonding curve discount uses spot price without TWAP - TempoDAO vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracle for bonding curve discount calculations".to_string(),
            });
        }

        if self.has_instant_bond_pricing() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "TempoDAO-style bonding curve discount oracle manipulation risk".to_string(),
                operations: Vec::new(),
                remediation: "Use time-weighted oracle prices for bonding curve calculations".to_string(),
            });
        }

        if self.has_missing_arbitrage_bounds() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Discount rate derived from manipulable single-block price".to_string(),
                operations: Vec::new(),
                remediation: "Implement multi-block price averaging for discount calculations".to_string(),
            });
        }

        warnings
    }

    fn has_spot_price_discount_calculation(&self) -> bool {
        // Pattern: price oracle call -> SUB (discount) -> MUL (bond amount)
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for oracle price fetch
            if self.bytecode[i] == 0xfa { // STATICCALL (to oracle)
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Check for discount calculation (SUB) followed by bond pricing (MUL)
                let has_discount = window.iter().enumerate().any(|(j, &op)| {
                    op == 0x03 && // SUB (apply discount)
                    window.get(j+1..j+5).map_or(false, |slice| {
                        slice.contains(&0x02) // MUL (calculate bond amount)
                    })
                });
                
                if has_discount {
                    // Check for TWAP (timestamp or observation array access)
                    let has_twap = window.iter().any(|&op| {
                        op == 0x42 || // TIMESTAMP
                        op == 0x54    // SLOAD (stored observations)
                    });
                    
                    if !has_twap {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_instant_bond_pricing(&self) -> bool {
        // Look for bond purchase without cooldown check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for bond minting (MINT selector or similar)
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Look for timestamp comparison (cooldown check)
                let has_cooldown = window.iter().any(|&op| {
                    op == 0x42 || // TIMESTAMP
                    op == 0x10 || // LT (time comparison)
                    op == 0x11    // GT
                });
                
                // Look for SSTORE (minting) without cooldown
                if window.contains(&0x55) && !has_cooldown {
                    return true;
                }
            }
        }
        false
    }

    fn has_missing_arbitrage_bounds(&self) -> bool {
        // Pattern: discount calculation without min/max bounds
        let mut has_discount = false;
        let mut has_bounds = false;
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for SUB (discount application)
            if self.bytecode[i] == 0x03 {
                has_discount = true;
                
                // Check next 15 opcodes for bounds checking
                let window = &self.bytecode[i..i+15.min(self.bytecode.len())];
                has_bounds = window.iter().any(|&op| {
                    op == 0x10 || // LT (lower bound)
                    op == 0x11 || // GT (upper bound)
                    op == 0x1b    // SLT
                });
                
                if has_discount && !has_bounds {
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
    fn test_tempo_dao_vulnerability() {
        let vulnerable_bytecode = vec![
            0xfa, // STATICCALL (oracle price)
            0x03, // SUB (apply discount)
            0x02, // MUL (calculate bond)
            0x55, // SSTORE (mint bond)
        ];

        let detector = TempoDaoBondingCurveDiscountDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty(), "Should detect TempoDAO bonding curve vulnerability");
    }

    #[test]
    fn test_safe_twap_bonding() {
        let safe_bytecode = vec![
            0x42, // TIMESTAMP (TWAP)
            0x54, // SLOAD (stored prices)
            0xfa, // STATICCALL
            0x11, // GT (bounds check)
            0x03, // SUB (discount)
            0x02, // MUL
        ];

        let detector = TempoDaoBondingCurveDiscountDetector::new(safe_bytecode);
        let warnings = detector.detect();
        assert!(warnings.is_empty(), "Safe TWAP bonding should not trigger");
    }
}
