use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Liquity Redemption Front-Running Detector
/// 
/// Detects MEV vulnerabilities in Liquity-style redemption mechanisms where
/// LUSD holders can redeem at $1 worth of ETH when LUSD trades below peg.
/// 
/// **MEV Strategy**: Liquity Redemption Front-Running ($10M+ extracted)
/// 
/// **Attack Pattern**:
/// 1. Monitor for LUSD price < $1 (e.g., $0.98)
/// 2. Front-run with large redemption to extract ETH at discount
/// 3. Redeem LUSD for $1 worth of ETH when market price is $0.98
/// 4. Profit: 2% on entire redemption amount
/// 5. Victims: Lowest collateralized troves get redeemed first
/// 
/// **Detection Strategy**:
/// - Identifies redemption mechanisms without anti-MEV protection
/// - Detects missing redemption cooldowns or rate limits
/// - Flags redemptions without minimum price deviation threshold
/// - Checks for lack of redemption fee scaling
/// - Validates trove ordering for fairness
pub struct LiquityRedemptionFrontrunDetector {
    bytecode: Vec<u8>,
}

impl LiquityRedemptionFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_redemption_without_mev_protection() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Redemption mechanism vulnerable to front-running MEV - Liquity pattern ($10M+ extracted)".to_string(),
                operations: Vec::new(),
                remediation: "Add redemption cooldowns, progressive fees, and minimum price deviation requirements".to_string(),
            });
        }

        if self.has_missing_redemption_cooldown() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "No cooldown period between redemptions - enables rapid MEV extraction".to_string(),
                operations: Vec::new(),
                remediation: "Implement per-user cooldown period (e.g., 12-24 hours) between redemptions".to_string(),
            });
        }

        if self.has_flat_redemption_fee() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Flat redemption fee doesn't scale with amount - large redemptions too cheap".to_string(),
                operations: Vec::new(),
                remediation: "Implement progressive fee structure that increases with redemption size".to_string(),
            });
        }

        if self.has_unfair_trove_ordering() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Trove redemption ordering may unfairly penalize smallest positions".to_string(),
                operations: Vec::new(),
                remediation: "Consider random or time-based ordering instead of pure collateral ratio sorting".to_string(),
            });
        }

        warnings
    }

    fn has_redemption_without_mev_protection(&self) -> bool {
        // Pattern: redeem() function without anti-MEV measures
        let redeem_selector = [0xdb, 0x00, 0x6a, 0x75]; // redeem()
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == redeem_selector {
                    let window = &self.bytecode[i..i+70.min(self.bytecode.len())];
                    
                    // Check for collateral transfer (redemption execution)
                    let has_redemption = window.iter().any(|&op| {
                        op == 0xf1 // CALL (transfer collateral)
                    });
                    
                    // Check for cooldown mechanism
                    let has_cooldown = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) && // SLOAD (last redemption)
                        w.iter().any(|&op| op == 0x10) // LT (time check)
                    });
                    
                    // Check for price deviation requirement
                    let has_price_check = window.windows(15).any(|w| {
                        // Pattern: peg price - current price > threshold
                        w.iter().any(|&op| op == 0x03) && // SUB (price diff)
                        w.iter().any(|&op| op == 0x11) && // GT (deviation > min)
                        w.iter().any(|&op| op == 0xfd) // REVERT if too small
                    });
                    
                    // Check for dynamic fee
                    let has_dynamic_fee = window.windows(12).any(|w| {
                        // Fee calculation based on amount or frequency
                        w.iter().any(|&op| op == 0x02) && // MUL (fee * amount)
                        w.iter().any(|&op| op == 0x04) // DIV (percentage)
                    });
                    
                    // Check for rate limiting
                    let has_rate_limit = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x54) && // SLOAD (total redeemed)
                        w.iter().any(|&op| op == 0x11) // GT (check limit)
                    });
                    
                    if has_redemption && !has_cooldown && !has_price_check && !has_dynamic_fee && !has_rate_limit {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_redemption_cooldown(&self) -> bool {
        // Pattern: redeem() without per-user time-based restriction
        let redeem_selector = [0xdb, 0x00, 0x6a, 0x75];
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == redeem_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    let has_redemption = window.contains(&0xf1);
                    
                    // Check for user-specific cooldown
                    let has_user_cooldown = window.windows(15).any(|w| {
                        // Pattern: KECCAK256(user) -> SLOAD(lastRedemption) -> TIMESTAMP check
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (user key)
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) // SLOAD
                    });
                    
                    if has_redemption && !has_user_cooldown {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_flat_redemption_fee(&self) -> bool {
        // Pattern: redemption fee not scaled by amount
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for fee calculation
            if self.bytecode[i] == 0x02 { // MUL (fee calculation)
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check if this is redemption-related
                let is_redemption_fee = window.windows(20).any(|w| {
                    w.iter().any(|&op| op == 0x04) && // DIV (percentage)
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) // PUSH (fee rate)
                });
                
                // Check if fee scales with amount
                let scales_with_amount = window.windows(15).any(|w| {
                    // Progressive fee: base_fee + (amount * scaling_factor)
                    w.iter().filter(|&&op| op == 0x02).count() >= 2 && // Multiple MUL
                    w.iter().any(|&op| op == 0x01) // ADD (base + scaled)
                });
                
                // Check if fee increases with frequency
                let scales_with_frequency = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (redemption count/time)
                    w.iter().any(|&op| op == 0x02) // MUL (fee * frequency)
                });
                
                if is_redemption_fee && !scales_with_amount && !scales_with_frequency {
                    return true;
                }
            }
        }
        false
    }

    fn has_unfair_trove_ordering(&self) -> bool {
        // Check if trove selection is purely based on collateral ratio
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for trove iteration/selection
            if self.bytecode[i] == 0x56 { // JUMP (loop through troves)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for collateral ratio sorting
                let sorts_by_ratio = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0x04) && // DIV (collateral/debt ratio)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // LT/GT (comparison)
                });
                
                // Check for randomization or fairness mechanism
                let has_randomization = window.windows(8).any(|w| {
                    w.iter().any(|&op| op == 0x44) || // PREVRANDAO
                    w.iter().any(|&op| op == 0x40) // BLOCKHASH
                });
                
                // Check for time-based selection
                let has_time_component = window.iter().any(|&op| {
                    op == 0x42 // TIMESTAMP (in selection)
                });
                
                if sorts_by_ratio && !has_randomization && !has_time_component {
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
    fn test_liquity_redemption_frontrun() {
        let vulnerable_bytecode = vec![
            0x63, 0xdb, 0x00, 0x6a, 0x75, // redeem()
            0xf1, // CALL (transfer collateral - no MEV protection!)
        ];

        let detector = LiquityRedemptionFrontrunDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("redemption") || w.description.contains("MEV")));
    }
}
