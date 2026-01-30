use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// 88mph Fixed Yield Manipulation Detector
/// 
/// Detects vulnerabilities in fixed-rate yield protocols where yield bonds
/// or ladder positions can be manipulated for profit.
/// 
/// **88mph Context**:
/// Users deposit assets and receive fixed-rate yield bonds (zero-coupon bonds).
/// Floating rate depositors receive excess yield. Fixed vs floating imbalance
/// can be exploited.
/// 
/// **Attack Patterns**:
/// 1. Fixed yield rate manipulation via oracle attacks
/// 2. Yield ladder exploitation (gaming maturity dates)
/// 3. Early withdrawal gaming to extract yield
/// 4. Floating/fixed ratio manipulation
/// 5. Bond pricing arbitrage
/// 
/// **Detection Strategy**:
/// - Identifies fixed rate calculation without oracle validation
/// - Detects yield ladder without maturity enforcement
/// - Flags early withdrawal without proper penalties
/// - Checks for bond pricing manipulation
/// - Validates floating/fixed balance ratios
pub struct EightymphFixedYieldDetector {
    bytecode: Vec<u8>,
}

impl EightymphFixedYieldDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_fixed_rate_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Fixed yield rate vulnerable to manipulation - 88mph pattern".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracles for yield rate calculation and add rate change limits".to_string(),
            });
        }

        if self.has_yield_ladder_exploitation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Yield ladder positions can be gamed via maturity date manipulation".to_string(),
                operations: Vec::new(),
                remediation: "Enforce strict maturity dates and prevent early claims without penalties".to_string(),
            });
        }

        if self.has_early_withdrawal_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Early withdrawals lack proper penalties allowing yield extraction".to_string(),
                operations: Vec::new(),
                remediation: "Implement progressive early withdrawal penalties based on time remaining".to_string(),
            });
        }

        if self.has_bond_pricing_arbitrage() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Fixed yield bond pricing vulnerable to arbitrage".to_string(),
                operations: Vec::new(),
                remediation: "Add bond pricing validation against market rates with acceptable bounds".to_string(),
            });
        }

        warnings
    }

    fn has_fixed_rate_manipulation(&self) -> bool {
        // Pattern: fixed rate calculation using manipulable yield source
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x04 { // DIV (yield rate calculation)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for yield rate calculation
                let calculates_yield_rate = window.windows(15).any(|w| {
                    // Pattern: totalYield / totalDeposits
                    w.iter().filter(|&&op| op == 0x54 || op == 0x31).count() >= 2 && // Load yield sources
                    w.iter().any(|&op| op == 0x04) // DIV
                });
                
                // Check if stored as fixed rate
                let stores_fixed_rate = window.windows(8).any(|w| {
                    w.iter().any(|&op| op == 0x55) && // SSTORE (fix the rate)
                    w.iter().any(|&op| op == 0x42) // TIMESTAMP (lock period)
                });
                
                if calculates_yield_rate && stores_fixed_rate {
                    // Check for TWAP oracle
                    let uses_twap = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().filter(|&&op| op == 0x54).count() >= 3 // Historical rates
                    });
                    
                    // Check for rate deviation limits
                    let has_deviation_limit = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x03) && // SUB (rate difference)
                        w.iter().any(|&op| op == 0x10) // LT (within bounds)
                    });
                    
                    if !uses_twap && !has_deviation_limit {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_yield_ladder_exploitation(&self) -> bool {
        // Pattern: maturity date not strictly enforced
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for maturity check
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                
                // Check for maturity comparison
                let checks_maturity = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (maturity date)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // LT/GT
                });
                
                if checks_maturity {
                    // Check for strict enforcement (must wait until maturity)
                    let enforces_strictly = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x10) && // LT (before maturity)
                        w.iter().any(|&op| op == 0xfd) // REVERT (can't claim early)
                    });
                    
                    // Check for proper penalty calculation
                    let has_penalty = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x03) && // SUB (remaining time)
                        w.iter().any(|&op| op == 0x02) && // MUL (penalty factor)
                        w.iter().any(|&op| op == 0x04) // DIV
                    });
                    
                    if !enforces_strictly && !has_penalty {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_early_withdrawal_gaming(&self) -> bool {
        // Pattern: withdraw before maturity without progressive penalty
        let withdraw_selector = [0x3c, 0xcf, 0xd6, 0x0b]; // withdraw()
        
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == withdraw_selector {
                    let window = &self.bytecode[i..i+55.min(self.bytecode.len())];
                    
                    // Check for maturity check
                    let checks_maturity = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) // SLOAD (maturity)
                    });
                    
                    // Check for withdrawal execution
                    let executes_withdrawal = window.contains(&0xf1); // CALL (transfer)
                    
                    if checks_maturity && executes_withdrawal {
                        // Check for progressive penalty
                        let has_progressive_penalty = window.windows(15).any(|w| {
                            // Penalty increases with time remaining
                            w.iter().any(|&op| op == 0x03) && // SUB (maturity - now)
                            w.iter().any(|&op| op == 0x02) && // MUL (time * penalty_rate)
                            w.iter().any(|&op| op == 0x04) // DIV (calculate penalty)
                        });
                        
                        // Check for minimum holding period
                        let has_min_holding = window.windows(12).any(|w| {
                            w.iter().any(|&op| op == 0x01) && // ADD (deposit_time + min_period)
                            w.iter().any(|&op| op == 0x10) && // LT (check if too early)
                            w.iter().any(|&op| op == 0xfd) // REVERT
                        });
                        
                        if !has_progressive_penalty && !has_min_holding {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_bond_pricing_arbitrage(&self) -> bool {
        // Pattern: bond price calculation without market validation
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x02 { // MUL (bond price calculation)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for bond pricing formula
                let calculates_bond_price = window.windows(15).any(|w| {
                    // Pattern: principal * (1 + rate * time)
                    w.iter().any(|&op| op == 0x02) && // MUL
                    w.iter().any(|&op| op == 0x01) && // ADD
                    w.iter().any(|&op| op == 0x04) // DIV
                });
                
                // Check for market price validation
                let validates_market_price = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL (market oracle)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // Compare
                });
                
                // Check for arbitrage bounds
                let has_bounds = window.windows(10).any(|w| {
                    w.iter().filter(|&&op| op >= 0x60 && op <= 0x7f).count() >= 2 && // Min/max bounds
                    w.iter().any(|&op| op == 0x10) // LT
                });
                
                if calculates_bond_price && !validates_market_price && !has_bounds {
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
    fn test_88mph_fixed_rate_manipulation() {
        let vulnerable_bytecode = vec![
            0x54, // SLOAD (yield)
            0x04, // DIV (calculate rate)
            0x55, // SSTORE (fix rate - no TWAP!)
            0x42, // TIMESTAMP (lock)
        ];

        let detector = EightymphFixedYieldDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("Fixed yield") || w.description.contains("rate")));
    }
}
