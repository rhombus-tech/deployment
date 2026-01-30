use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Ribbon/Structured Vault Option Mispricing Detector
/// 
/// Detects vulnerabilities in automated options vaults where strike price selection,
/// premium calculation, or option settlement can be manipulated.
/// 
/// **Ribbon Context**:
/// Ribbon vaults auto-sell covered calls/puts on deposits. Key operations:
/// - Weekly options minting with algorithmically selected strikes
/// - Premium collection and distribution
/// - Option settlement and vault rebalancing
/// 
/// **Attack Patterns**:
/// 1. Strike price manipulation via oracle attacks
/// 2. Premium extraction through mispriced options
/// 3. Settlement timing manipulation
/// 4. Vault deposit front-running before option sale
/// 5. Withdrawal gaming around settlement
/// 
/// **Detection Strategy**:
/// - Identifies strike selection without oracle validation
/// - Detects premium calculations using manipulable prices
/// - Flags settlement without proper price checks
/// - Checks for deposit/withdrawal timing attacks
/// - Validates option parameter bounds
pub struct RibbonStructuredVaultDetector {
    bytecode: Vec<u8>,
}

impl RibbonStructuredVaultDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_strike_price_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Option strike price selection vulnerable to oracle manipulation - Ribbon pattern".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracles for strike selection and add deviation limits from spot".to_string(),
            });
        }

        if self.has_premium_mispricing_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Option premium calculation vulnerable to mispricing".to_string(),
                operations: Vec::new(),
                remediation: "Validate premium against Black-Scholes or market prices with acceptable bounds".to_string(),
            });
        }

        if self.has_settlement_timing_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Option settlement timing can be manipulated for advantageous pricing".to_string(),
                operations: Vec::new(),
                remediation: "Use predetermined settlement times and price snapshots".to_string(),
            });
        }

        if self.has_deposit_frontrun_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Deposits can be front-run before option sale to dilute existing shares".to_string(),
                operations: Vec::new(),
                remediation: "Add deposit queue with time delay before option minting epoch".to_string(),
            });
        }

        warnings
    }

    fn has_strike_price_manipulation(&self) -> bool {
        // Pattern: strike price selection using spot price without TWAP
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0xfa { // STATICCALL (to oracle)
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check if used for strike calculation
                let used_for_strike = window.windows(15).any(|w| {
                    // Pattern: oraclePrice * strikeMultiplier
                    w.iter().any(|&op| op == 0x02) && // MUL
                    w.iter().any(|&op| op == 0x55) // SSTORE (store strike)
                });
                
                // Check for TWAP validation
                let has_twap = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 // Historical prices
                });
                
                // Check for deviation limit
                let has_deviation_check = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x03) && // SUB (price difference)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // LT/GT
                });
                
                if used_for_strike && !has_twap && !has_deviation_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_premium_mispricing_risk(&self) -> bool {
        // Pattern: premium calculation without validation
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x02 { // MUL (premium calculation)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for option premium calculation
                let calculates_premium = window.windows(15).any(|w| {
                    // Pattern: notional * premium_rate
                    w.iter().filter(|&&op| op == 0x02).count() >= 1 && // MUL
                    w.iter().any(|&op| op == 0x04) // DIV (percentage)
                });
                
                // Check for Black-Scholes or market price validation
                let validates_premium = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL (to pricer)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // Compare
                });
                
                // Check for premium bounds
                let has_bounds = window.windows(8).any(|w| {
                    w.iter().filter(|&&op| op >= 0x60 && op <= 0x7f).count() >= 2 && // PUSH min/max
                    w.iter().any(|&op| op == 0x10) // LT
                });
                
                if calculates_premium && !validates_premium && !has_bounds {
                    return true;
                }
            }
        }
        false
    }

    fn has_settlement_timing_manipulation(&self) -> bool {
        // Pattern: settlement without predetermined time
        let settle_selector = [0x5e, 0x8a, 0x79, 0x1b]; // settle() or closeRound()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == settle_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for settlement execution
                    let settles_options = window.contains(&0xf1); // CALL (settlement)
                    
                    // Check for predetermined time enforcement
                    let has_fixed_time = window.windows(10).any(|w| {
                        // Pattern: TIMESTAMP >= predeterminedSettlementTime
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) && // SLOAD (settlement time)
                        w.iter().any(|&op| op == 0x10 || op == 0x11) // Compare
                    });
                    
                    // Check for price snapshot usage
                    let uses_snapshot = window.windows(8).any(|w| {
                        // Use stored price, not current
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (snapshot key)
                        w.iter().any(|&op| op == 0x54) // SLOAD
                    });
                    
                    if settles_options && !has_fixed_time && !uses_snapshot {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_deposit_frontrun_vulnerability(&self) -> bool {
        // Pattern: deposit immediately affects next option sale
        let deposit_selector = [0xb6, 0xb5, 0x5f, 0x25]; // deposit()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == deposit_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for share minting
                    let mints_shares = window.windows(5).any(|w| {
                        w.iter().any(|&op| op == 0x01) && // ADD (mint shares)
                        w.iter().any(|&op| op == 0x55) // SSTORE
                    });
                    
                    // Check for deposit queue/delay
                    let has_queue = window.windows(10).any(|w| {
                        // Pattern: add to pending deposits
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (queue key)
                        w.iter().any(|&op| op == 0x55) // SSTORE (pending)
                    });
                    
                    // Check for epoch-based processing
                    let has_epoch_delay = window.windows(8).any(|w| {
                        // Check current epoch vs deposit epoch
                        w.iter().filter(|&&op| op == 0x54).count() >= 2 // SLOAD epochs
                    });
                    
                    if mints_shares && !has_queue && !has_epoch_delay {
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
    fn test_ribbon_strike_manipulation() {
        let vulnerable_bytecode = vec![
            0xfa, // STATICCALL (oracle - spot price)
            0x02, // MUL (strike = spot * multiplier)
            0x55, // SSTORE (no TWAP validation!)
        ];

        let detector = RibbonStructuredVaultDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("strike") || w.description.contains("oracle")));
    }
}
