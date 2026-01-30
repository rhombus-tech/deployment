// Ribbon v2 Auction Participation Gaming Detector
// Detects manipulation of options auction mechanism (GnosisAuction integration)

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RibbonAuctionVulnerability {
    pub location: usize,
    pub vulnerability_type: RibbonVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RibbonVulnerabilityType {
    AuctionClearingPriceManipulation,  // Manipulate auction clearing price
    BidSubmissionRaceCondition,          // Front-run auction settlement
    MinimumBidRequirementBypass,         // Submit bids below minimum
    AuctionEndTimeManipulation,          // Extend auction via timestamp gaming
    PartialFillExploit,                  // Exploit partial fill rounding
    WithdrawalQueueGriefing,             // DoS withdrawal queue
    PremiumCalculationError,             // Incorrect premium distribution
}

pub struct RibbonAuctionDetector {
    bytecode: Vec<u8>,
}

impl RibbonAuctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RibbonAuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_clearing_price_manipulation() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::AuctionClearingPriceManipulation,
                severity: SecuritySeverity::Critical,
                description: "Auction clearing price determined by single block snapshot. Large \
                             bidder can manipulate price by submitting/canceling bids within \
                             same block to affect all participants.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_bid_race_condition() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::BidSubmissionRaceCondition,
                severity: SecuritySeverity::High,
                description: "Auction settlement can be front-run. MEV bot can observe clearing \
                             price in mempool and submit last-minute bid to get favorable fill.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_minimum_bid_bypass() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::MinimumBidRequirementBypass,
                severity: SecuritySeverity::Medium,
                description: "Minimum bid requirement check uses strict equality. Bidder can \
                             bypass by submitting bid at exactly minimum minus 1 wei.".to_string(),
                confidence: 0.75,
            });
        }

        if let Some(loc) = self.detect_auction_time_manipulation() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::AuctionEndTimeManipulation,
                severity: SecuritySeverity::High,
                description: "Auction end time uses block.timestamp without buffer. Validator \
                             can manipulate timestamp to extend auction and submit favorable bids.".to_string(),
                confidence: 0.79,
            });
        }

        if let Some(loc) = self.detect_partial_fill_exploit() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::PartialFillExploit,
                severity: SecuritySeverity::Medium,
                description: "Partial fill calculation rounds down without accumulating dust. \
                             Multiple small bids can extract value through rounding errors.".to_string(),
                confidence: 0.73,
            });
        }

        if let Some(loc) = self.detect_withdrawal_queue_griefing() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::WithdrawalQueueGriefing,
                severity: SecuritySeverity::Medium,
                description: "Withdrawal queue processes linearly without gas limit. Attacker \
                             can spam small withdrawals to DoS queue processing.".to_string(),
                confidence: 0.70,
            });
        }

        if let Some(loc) = self.detect_premium_calculation_error() {
            vulnerabilities.push(RibbonAuctionVulnerability {
                location: loc,
                vulnerability_type: RibbonVulnerabilityType::PremiumCalculationError,
                severity: SecuritySeverity::High,
                description: "Premium distribution uses integer division without remainder \
                             tracking. Final bidder receives all dust, creating unfair advantage.".to_string(),
                confidence: 0.76,
            });
        }

        vulnerabilities
    }

    fn detect_clearing_price_manipulation(&self) -> Option<usize> {
        // Pattern: Single price snapshot for auction clearing
        // CALL (get bids) → single DIV/MUL (price calc) → SSTORE (clearing price)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {
                let mut has_price_calc = false;
                let mut has_multi_snapshot = false;
                let mut call_count = 1;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                        call_count += 1;
                        if call_count >= 2 {
                            has_multi_snapshot = true;
                        }
                    }
                    
                    if self.bytecode[j] == 0x04 || self.bytecode[j] == 0x02 {  // DIV/MUL
                        has_price_calc = true;
                    }
                    
                    if has_price_calc && !has_multi_snapshot && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_bid_race_condition(&self) -> Option<usize> {
        // Pattern: Settlement without commit-reveal or delay
        // TIMESTAMP → LT (deadline check) → SSTORE (settle) without SLOAD (commit hash)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_deadline = false;
                let mut has_commit_check = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_deadline = true;
                    }
                    
                    if self.bytecode[j] == 0x54 {  // SLOAD (check commit)
                        has_commit_check = true;
                    }
                    
                    if has_deadline && !has_commit_check && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_minimum_bid_bypass(&self) -> Option<usize> {
        // Pattern: Strict EQ instead of GTE for minimum check
        // PUSH (minimum) → EQ → REVERT (bad, should be LT → ISZERO → REVERT)
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if matches!(self.bytecode[i], 0x60..=0x7F) {  // PUSH
                for j in i+1..(i+8).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (strict equality)
                        // Check if this is for bid validation
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xFD || self.bytecode[k] == 0x57 {  // REVERT/JUMPI
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_auction_time_manipulation(&self) -> Option<usize> {
        // Pattern: TIMESTAMP used for deadline without safety buffer
        // TIMESTAMP → LT (end check) without SUB (buffer)
        
        for i in 0..self.bytecode.len().saturating_sub(12) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_buffer = false;
                
                for j in i+1..(i+10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 {  // SUB (buffer calculation)
                        has_buffer = true;
                    }
                    
                    if !has_buffer && (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_partial_fill_exploit(&self) -> Option<usize> {
        // Pattern: DIV for partial fill without MOD to track remainder
        // MUL (bid amount) → DIV (fill calc) without MOD + SSTORE (dust tracking)
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x02 {  // MUL
                let mut has_division = false;
                let mut has_mod = false;
                
                for j in i+1..(i+12).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        has_division = true;
                    }
                    
                    if self.bytecode[j] == 0x06 {  // MOD
                        has_mod = true;
                    }
                    
                    if has_division && !has_mod && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_withdrawal_queue_griefing(&self) -> Option<usize> {
        // Pattern: Loop over withdrawals without gas check
        // JUMPDEST (loop) → SLOAD → CALL → JUMPI (continue) without GAS opcode
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (potential loop)
                let mut has_iteration = false;
                let mut has_gas_check = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 || self.bytecode[j] == 0xF1 {  // SLOAD/CALL
                        has_iteration = true;
                    }
                    
                    if self.bytecode[j] == 0x5A {  // GAS
                        has_gas_check = true;
                    }
                    
                    if has_iteration && !has_gas_check && self.bytecode[j] == 0x57 {  // JUMPI
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_premium_calculation_error(&self) -> Option<usize> {
        // Pattern: Division for premium distribution without remainder handling
        // DIV (distribute premium) → SSTORE without prior MOD → ADD → SSTORE pattern
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 {  // DIV
                let mut has_remainder_handling = false;
                let mut store_count = 0;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // Look for MOD followed by ADD (proper remainder handling)
                    if self.bytecode[j] == 0x06 {  // MOD
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD
                                has_remainder_handling = true;
                            }
                        }
                    }
                    
                    if self.bytecode[j] == 0x55 {  // SSTORE
                        store_count += 1;
                    }
                    
                    // Multiple stores without remainder handling
                    if store_count >= 2 && !has_remainder_handling {
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
                kind: SecurityWarningKind::RibbonV2Auction,
                severity: v.severity,
                description: format!(
                    "Ribbon Auction {:?} at PC {}: {}",
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
    fn test_clearing_price_manipulation() {
        let bytecode = vec![
            0xF1, // CALL (get bids)
            0x60, 0x0A, // PUSH1 10
            0x04, // DIV (calculate price)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (store price)
        ];
        
        let detector = RibbonAuctionDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RibbonVulnerabilityType::AuctionClearingPriceManipulation)));
    }

    #[test]
    fn test_partial_fill_rounding() {
        let bytecode = vec![
            0x02, // MUL (bid amount)
            0x60, 0x64, // PUSH1 100
            0x04, // DIV (calculate fill)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no MOD tracking)
        ];
        
        let detector = RibbonAuctionDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RibbonVulnerabilityType::PartialFillExploit)));
    }
}
