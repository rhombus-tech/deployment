use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// DODO Proactive Market Maker (PMM) Algorithm Manipulation Detector
/// 
/// Detects vulnerabilities in DODO's PMM algorithm where price curve manipulation
/// via oracle attacks or liquidity manipulation enables arbitrage extraction.
/// 
/// **DODO PMM Context**:
/// DODO uses a Proactive Market Maker algorithm that adjusts price curves based on:
/// - External oracle prices (mid-price)
/// - Liquidity depth (base/quote token balances)
/// - Slippage parameter (k factor)
/// 
/// **Attack Patterns**:
/// 1. Oracle price manipulation to shift PMM curve
/// 2. Liquidity imbalance exploitation
/// 3. K-factor manipulation for favorable pricing
/// 4. Flash loan attacks to drain one side of pool
/// 5. Price curve reset gaming
/// 
/// **Detection Strategy**:
/// - Identifies PMM price calculations using manipulable oracles
/// - Detects missing liquidity depth validation
/// - Flags k-factor updates without bounds
/// - Checks for flash loan vulnerability in PMM reset
/// - Validates price impact limits
pub struct DodoPmmAlgorithmDetector {
    bytecode: Vec<u8>,
}

impl DodoPmmAlgorithmDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_pmm_oracle_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "PMM algorithm uses manipulable oracle for mid-price - DODO vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracle for PMM mid-price and add deviation limits from spot price".to_string(),
            });
        }

        if self.has_liquidity_imbalance_exploitation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "PMM price curve vulnerable to liquidity imbalance attacks".to_string(),
                operations: Vec::new(),
                remediation: "Add liquidity depth validation and minimum reserves for PMM operation".to_string(),
            });
        }

        if self.has_k_factor_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "PMM k-factor (slippage parameter) can be manipulated".to_string(),
                operations: Vec::new(),
                remediation: "Restrict k-factor updates with bounds and timelock requirements".to_string(),
            });
        }

        if self.has_pmm_reset_flash_loan_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::FlashLoanAttackVector,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "PMM curve reset vulnerable to flash loan manipulation".to_string(),
                operations: Vec::new(),
                remediation: "Add flash loan guards to PMM reset functions".to_string(),
            });
        }

        warnings
    }

    fn has_pmm_oracle_manipulation(&self) -> bool {
        // Pattern: PMM price calculation using oracle without TWAP
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for oracle call
            if self.bytecode[i] == 0xfa { // STATICCALL (to oracle)
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check if result used in price curve calculation
                let used_in_price_calc = window.windows(15).any(|w| {
                    // Pattern: oraclePrice used in PMM formula
                    w.iter().any(|&op| op == 0x02 || op == 0x04) && // MUL/DIV (price calculation)
                    w.iter().any(|&op| op == 0x31 || op == 0x54) // BALANCE or SLOAD (liquidity)
                });
                
                // Check for TWAP validation
                let has_twap = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP (for TWAP)
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 // Multiple SLOAD (historical prices)
                });
                
                // Check for price deviation limit
                let has_deviation_check = window.windows(8).any(|w| {
                    w.iter().any(|&op| op == 0x03) && // SUB (price difference)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // LT/GT (check deviation)
                });
                
                if used_in_price_calc && !has_twap && !has_deviation_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_liquidity_imbalance_exploitation(&self) -> bool {
        // Pattern: PMM calculation without minimum liquidity checks
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x04 { // DIV (in PMM formula)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for PMM-style calculation (base/quote ratio)
                let has_pmm_calc = window.windows(12).any(|w| {
                    w.iter().filter(|&&op| op == 0x31 || op == 0x54).count() >= 2 && // Multiple balance/reserve reads
                    w.iter().any(|&op| op == 0x02) // MUL
                });
                
                // Check for minimum liquidity validation
                let has_min_liquidity = window.windows(8).any(|w| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (min amount)
                    w.iter().any(|&op| op == 0x11) && // GT (balance > min)
                    w.iter().any(|&op| op == 0xfd) // REVERT if insufficient
                });
                
                // Check for imbalance ratio limit
                let has_ratio_limit = window.windows(10).any(|w| {
                    // Pattern: base/quote ratio within acceptable range
                    w.iter().filter(|&&op| op == 0x10 || op == 0x11).count() >= 2 // Multiple comparisons
                });
                
                if has_pmm_calc && !has_min_liquidity && !has_ratio_limit {
                    return true;
                }
            }
        }
        false
    }

    fn has_k_factor_manipulation(&self) -> bool {
        // Pattern: k-factor update without proper controls
        let set_k = [0x9d, 0x61, 0xd2, 0x34]; // setK() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == set_k {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check for k-factor storage update
                    let updates_k = window.contains(&0x55); // SSTORE
                    
                    // Check for k-factor bounds validation
                    let has_bounds = window.windows(8).any(|w| {
                        // Pattern: k > minK && k < maxK
                        w.iter().filter(|&&op| op == 0x10 || op == 0x11).count() >= 2
                    });
                    
                    // Check for timelock
                    let has_timelock = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x42) // TIMESTAMP
                    });
                    
                    if updates_k && !has_bounds && !has_timelock {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_pmm_reset_flash_loan_vulnerability(&self) -> bool {
        // Pattern: reset() function vulnerable to flash loans
        let reset_selector = [0xd8, 0x26, 0xf8, 0x8f]; // reset()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == reset_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for PMM state reset
                    let resets_pmm_state = window.iter().filter(|&&op| op == 0x55).count() >= 2;
                    
                    // Check for flash loan guard
                    let has_flash_guard = window.windows(8).any(|w| {
                        // Block number check
                        w.iter().any(|&op| op == 0x43) && // NUMBER
                        w.iter().any(|&op| op == 0x54) // SLOAD (last reset block)
                    });
                    
                    if resets_pmm_state && !has_flash_guard {
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
    fn test_dodo_pmm_oracle_manipulation() {
        let vulnerable_bytecode = vec![
            0xfa, // STATICCALL (oracle)
            0x02, // MUL (use in PMM calc)
            0x31, // BALANCE (liquidity)
            0x04, // DIV (PMM price - no TWAP!)
        ];

        let detector = DodoPmmAlgorithmDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("PMM") || w.description.contains("oracle")));
    }
}
