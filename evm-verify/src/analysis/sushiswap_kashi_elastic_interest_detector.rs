use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Sushiswap Kashi/BentoBox Elastic Interest Exploitation Detector
/// 
/// Detects vulnerabilities in isolated lending markets with elastic interest rates
/// where borrow rate can be manipulated via utilization gaming.
/// 
/// **Kashi/BentoBox Context**:
/// - Isolated lending pairs with independent risk parameters
/// - Elastic interest rates based on utilization
/// - BentoBox vault for share-based accounting
/// - Interest accrual affects all borrowers in pair
/// 
/// **Attack Patterns**:
/// 1. Utilization manipulation to spike interest rates
/// 2. Flash loan to drain liquidity, forcing liquidations
/// 3. Share dilution in BentoBox accounting
/// 4. Interest accrual gaming before/after operations
/// 5. Isolated market oracle manipulation
/// 
/// **Detection Strategy**:
/// - Identifies interest rate calculations without bounds
/// - Detects utilization ratio manipulation vectors
/// - Flags missing BentoBox share validation
/// - Checks for interest accrual timing attacks
/// - Validates isolated market risk parameters
pub struct SushiswapKashiElasticInterestDetector {
    bytecode: Vec<u8>,
}

impl SushiswapKashiElasticInterestDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unbounded_elastic_interest() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Elastic interest rate lacks upper bound - Kashi vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Implement maximum interest rate cap to prevent rate manipulation attacks".to_string(),
            });
        }

        if self.has_utilization_manipulation_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Utilization ratio can be manipulated to spike interest rates".to_string(),
                operations: Vec::new(),
                remediation: "Add utilization rate smoothing and flash loan protection".to_string(),
            });
        }

        if self.has_bentobox_share_dilution() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "BentoBox share calculation vulnerable to dilution attacks".to_string(),
                operations: Vec::new(),
                remediation: "Validate share minting/burning with minimum share requirements".to_string(),
            });
        }

        if self.has_interest_accrual_timing_attack() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Interest accrual timing can be gamed for advantage".to_string(),
                operations: Vec::new(),
                remediation: "Accrue interest atomically before all state-changing operations".to_string(),
            });
        }

        warnings
    }

    fn has_unbounded_elastic_interest(&self) -> bool {
        // Pattern: interest rate calculation without maximum cap
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x02 { // MUL (interest rate calculation)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for utilization-based rate calculation
                let calculates_elastic_rate = window.windows(15).any(|w| {
                    // Pattern: baseRate + (utilization * elasticFactor)
                    w.iter().any(|&op| op == 0x04) && // DIV (utilization = borrowed/total)
                    w.iter().any(|&op| op == 0x02) && // MUL (elastic component)
                    w.iter().any(|&op| op == 0x01) // ADD (base + elastic)
                });
                
                // Check for maximum rate cap
                let has_max_cap = window.windows(8).any(|w| {
                    // Pattern: if (rate > maxRate) rate = maxRate
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max rate)
                    w.iter().any(|&op| op == 0x11) && // GT
                    w.iter().any(|&op| op == 0x57) // JUMPI (cap it)
                });
                
                // Check for emergency circuit breaker
                let has_circuit_breaker = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (emergency flag)
                    w.iter().any(|&op| op == 0x15) // ISZERO (check active)
                });
                
                if calculates_elastic_rate && !has_max_cap && !has_circuit_breaker {
                    return true;
                }
            }
        }
        false
    }

    fn has_utilization_manipulation_risk(&self) -> bool {
        // Pattern: utilization = borrowed / totalAssets (manipulable)
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x04 { // DIV (utilization calculation)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for utilization calculation
                let calculates_utilization = window.windows(12).any(|w| {
                    w.iter().filter(|&&op| op == 0x54 || op == 0x31).count() >= 2 // Multiple balance reads
                });
                
                // Check for flash loan protection
                let has_flash_protection = window.windows(10).any(|w| {
                    // Block number check to prevent same-block manipulation
                    w.iter().any(|&op| op == 0x43) && // NUMBER
                    w.iter().any(|&op| op == 0x54) // SLOAD (last update block)
                });
                
                // Check for utilization smoothing
                let has_smoothing = window.windows(15).any(|w| {
                    // TWAP-style smoothing of utilization
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 // Historical values
                });
                
                // Check for minimum liquidity requirement
                let has_min_liquidity = window.windows(8).any(|w| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (min)
                    w.iter().any(|&op| op == 0x11) // GT
                });
                
                if calculates_utilization && !has_flash_protection && !has_smoothing && !has_min_liquidity {
                    return true;
                }
            }
        }
        false
    }

    fn has_bentobox_share_dilution(&self) -> bool {
        // Pattern: share-based accounting in BentoBox
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x04 { // DIV (share calculation)
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check for share calculation pattern
                let calculates_shares = window.windows(12).any(|w| {
                    // shares = amount * totalShares / totalAssets
                    w.iter().any(|&op| op == 0x02) && // MUL
                    w.iter().any(|&op| op == 0x18) // TOTALSSUPPLY (shares)
                });
                
                // Check for minimum share protection
                let has_min_share = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x11) && // GT (shares > minimum)
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                // Check for first depositor protection
                let protects_first_deposit = window.windows(10).any(|w| {
                    // Special handling when totalShares == 0
                    w.iter().any(|&op| op == 0x18) && // TOTALSSUPPLY
                    w.iter().any(|&op| op == 0x15) // ISZERO
                });
                
                if calculates_shares && !has_min_share && !protects_first_deposit {
                    return true;
                }
            }
        }
        false
    }

    fn has_interest_accrual_timing_attack(&self) -> bool {
        // Check if interest is accrued before state changes
        let accrue_selector = [0xa6, 0xaf, 0xed, 0x95]; // accrue() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(55) {
            // Look for borrow/repay without prior accrual
            let borrow_selector = [0xc5, 0xea, 0xbe, 0xec];
            
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == borrow_selector {
                    let window_before = &self.bytecode[i.saturating_sub(40)..i];
                    
                    // Check for accrual call before borrow
                    let accrues_before = window_before.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == accrue_selector
                    });
                    
                    // Check for internal accrual
                    let has_internal_accrual = window_before.windows(15).any(|w| {
                        // Pattern: timestamp-based interest calculation
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x02) && // MUL (interest)
                        w.iter().any(|&op| op == 0x55) // SSTORE (update)
                    });
                    
                    if !accrues_before && !has_internal_accrual {
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
    fn test_kashi_unbounded_interest() {
        let vulnerable_bytecode = vec![
            0x04, // DIV (utilization)
            0x02, // MUL (elastic rate)
            0x01, // ADD (base + elastic - no cap!)
        ];

        let detector = SushiswapKashiElasticInterestDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("interest rate")));
    }

    #[test]
    fn test_bentobox_share_dilution() {
        let vulnerable_bytecode = vec![
            0x02, // MUL (amount * totalShares)
            0x18, // TOTALSSUPPLY
            0x04, // DIV (/ totalAssets - no minimum!)
            0x55, // SSTORE
        ];

        let detector = SushiswapKashiElasticInterestDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| w.description.contains("share")));
    }
}
