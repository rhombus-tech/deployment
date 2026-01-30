// friend.tech Subject Share Manipulation Detector
// Detects manipulation of social token bonding curves and share trading

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendTechVulnerability {
    pub location: usize,
    pub vulnerability_type: FriendTechVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FriendTechVulnerabilityType {
    BondingCurveManipulation,       // Price curve manipulation
    ShareDumpProtectionBypass,      // Bypass anti-dump mechanics
    ProtocolFeeEvasion,             // Evade protocol/subject fees
    FirstShareAdvantage,            // Exploit first share pricing
    SlippageExploitation,           // Sandwich share purchases
    KeyHolderVerificationBypass,    // Fake key holder status
    RoyaltyCalculationError,        // Incorrect fee distribution
}

pub struct FriendTechDetector {
    bytecode: Vec<u8>,
}

impl FriendTechDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FriendTechVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_bonding_curve_manipulation() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::BondingCurveManipulation,
                severity: SecuritySeverity::Critical,
                description: "Bonding curve price calculation overflow. Large share counts cause \
                             price calculation to wrap around, allowing shares at incorrect prices.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_dump_protection_bypass() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::ShareDumpProtectionBypass,
                severity: SecuritySeverity::High,
                description: "Share sale limits can be bypassed through multiple transactions. \
                             No cumulative volume tracking allows dumping beyond intended limits.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_fee_evasion() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::ProtocolFeeEvasion,
                severity: SecuritySeverity::High,
                description: "Protocol fee calculation uses unchecked arithmetic. Large trades can \
                             cause fee underflow, allowing trades with minimal or zero fees.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_first_share_exploit() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::FirstShareAdvantage,
                severity: SecuritySeverity::Medium,
                description: "First share purchase lacks frontrun protection. Bots can monitor new \
                             subject creation and buy first share before creator.".to_string(),
                confidence: 0.76,
            });
        }

        if let Some(loc) = self.detect_slippage_exploitation() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::SlippageExploitation,
                severity: SecuritySeverity::High,
                description: "Share purchase lacks slippage protection. MEV can sandwich large buys \
                             to profit from bonding curve price movement.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_keyholder_bypass() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::KeyHolderVerificationBypass,
                severity: SecuritySeverity::Medium,
                description: "Key holder status check uses balance snapshot. Flashloan can fake \
                             ownership to access gated content.".to_string(),
                confidence: 0.74,
            });
        }

        if let Some(loc) = self.detect_royalty_calculation_error() {
            vulnerabilities.push(FriendTechVulnerability {
                location: loc,
                vulnerability_type: FriendTechVulnerabilityType::RoyaltyCalculationError,
                severity: SecuritySeverity::Medium,
                description: "Subject royalty rounds down systematically. High-volume traders lose \
                             significant fees to rounding over time.".to_string(),
                confidence: 0.72,
            });
        }

        vulnerabilities
    }

    fn detect_bonding_curve_manipulation(&self) -> Option<usize> {
        // Pattern: Price calculation with MUL/EXP without overflow check
        // share_count ** 2 can overflow for large counts
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x0A || self.bytecode[i] == 0x02 {  // EXP or MUL
                let mut has_overflow_check = false;
                
                // Check for overflow protection
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x80..=0x8F) ||  // DUP
                       matches!(self.bytecode[j], 0x10 | 0x11) {   // LT/GT
                        has_overflow_check = true;
                    }
                }
                
                // Price calculation stored without check
                if !has_overflow_check {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (price)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_dump_protection_bypass(&self) -> Option<usize> {
        // Pattern: Sale limit without cumulative tracking
        // LT check without SLOAD (cumulative volume)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x10 {  // LT (amount check)
                let mut checks_cumulative = false;
                
                // Check if cumulative volume is loaded
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        // Check if it's added to current amount
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (cumulative)
                                checks_cumulative = true;
                            }
                        }
                    }
                }
                
                // Check if this is a sell operation (SUB nearby)
                let mut is_sell = false;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 {  // SUB (reduce shares)
                        is_sell = true;
                    }
                }
                
                if is_sell && !checks_cumulative {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_fee_evasion(&self) -> Option<usize> {
        // Pattern: Fee calculation without SafeMath
        // MUL (amount * fee_percent) → DIV without overflow check
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 {  // MUL (fee calculation)
                let mut has_safety = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // SafeMath or overflow check
                    if matches!(self.bytecode[j], 0x80..=0x8F) {  // DUP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {
                                has_safety = true;
                            }
                        }
                    }
                    
                    if self.bytecode[j] == 0x04 {  // DIV
                        if !has_safety {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_first_share_exploit(&self) -> Option<usize> {
        // Pattern: First buy without commit-reveal
        // ISZERO (supply == 0) → buy without commitment check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x15 {  // ISZERO (check if first)
                let mut has_commit = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Check for commitment hash verification
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify hash)
                                has_commit = true;
                            }
                        }
                    }
                    
                    // First buy executed without commit
                    if !has_commit && self.bytecode[j] == 0x55 {  // SSTORE (purchase)
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_slippage_exploitation(&self) -> Option<usize> {
        // Pattern: Buy/sell without minAmountOut parameter
        // Price calculation without LT (min price check)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for price calculation
            if self.bytecode[i] == 0x04 || self.bytecode[i] == 0x02 {  // DIV/MUL (price)
                let mut has_slippage_check = false;
                
                // Check for min amount comparison
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (slippage)
                        has_slippage_check = true;
                    }
                }
                
                // Check if this leads to state change (trade)
                if !has_slippage_check {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (execute)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_keyholder_bypass(&self) -> Option<usize> {
        // Pattern: Balance check without flashloan protection
        // SLOAD (balance) → GT without block.number comparison
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 {  // SLOAD (balance)
                let mut has_flashloan_check = false;
                
                // Check for block.number or timestamp comparison
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 || self.bytecode[j] == 0x42 {  // NUMBER/TIMESTAMP
                        has_flashloan_check = true;
                    }
                }
                
                // Balance used for access control
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 {  // GT (has shares)
                        if !has_flashloan_check && j+5 < self.bytecode.len() {
                            if self.bytecode[j+4] == 0x57 {  // JUMPI (gate)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_royalty_calculation_error(&self) -> Option<usize> {
        // Pattern: Royalty DIV without MOD tracking
        // MUL (total fee) → DIV (split) without remainder handling
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 {  // MUL (calculate fee)
                let mut has_division = false;
                let mut tracks_remainder = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        has_division = true;
                    }
                    
                    if self.bytecode[j] == 0x06 {  // MOD (remainder)
                        tracks_remainder = true;
                    }
                    
                    // Division without remainder tracking
                    if has_division && !tracks_remainder && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::FriendTech,
                severity: v.severity,
                description: format!(
                    "friend.tech {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bonding_curve_overflow() {
        let bytecode = vec![
            0x0A, // EXP (price = shares^2)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no overflow check)
        ];
        
        let detector = FriendTechDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, FriendTechVulnerabilityType::BondingCurveManipulation)));
    }

    #[test]
    fn test_slippage_missing() {
        let bytecode = vec![
            0x02, // MUL (calculate price)
            0x60, 0x64, // PUSH1 100
            0x04, // DIV
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no slippage check)
        ];
        
        let detector = FriendTechDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, FriendTechVulnerabilityType::SlippageExploitation)));
    }
}
