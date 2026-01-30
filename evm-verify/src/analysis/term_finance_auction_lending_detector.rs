use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Term Finance Auction-Based Lending Detector
/// 
/// Detects vulnerabilities in Term Finance's periodic auction mechanism for matching
/// borrowers and lenders, where auction manipulation or term mismatch can be exploited.
/// 
/// **Term Finance Context**:
/// Term uses periodic auctions to match fixed-term loans:
/// - Borrowers submit bids with desired rates
/// - Lenders submit offers with minimum rates
/// - Auction clears at market-clearing rate
/// - Fixed terms (e.g., 1 week, 1 month)
/// 
/// **Attack Patterns**:
/// 1. Auction manipulation - submitting bids to manipulate clearing rate
/// 2. Term mismatch exploitation - rolling over loans unfavorably
/// 3. Clearing price gaming - sniping optimal rates
/// 4. Auction timing attacks - last-block bid manipulation
/// 5. Partial fill exploitation - gaming fill priorities
/// 
/// **Detection Strategy**:
/// - Identifies auction clearing without manipulation protection
/// - Detects term rollover vulnerabilities
/// - Flags clearing price calculation gaps
/// - Checks for bid/offer validation
/// - Validates auction finalization integrity
pub struct TermFinanceAuctionLendingDetector {
    bytecode: Vec<u8>,
}

impl TermFinanceAuctionLendingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_auction_clearing_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Term auction clearing rate manipulable via coordinated bids".to_string(),
                operations: Vec::new(),
                remediation: "Add bid concentration limits and Sybil resistance to auction clearing".to_string(),
            });
        }

        if self.has_term_rollover_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Loan term rollover exposed to unfavorable rate changes".to_string(),
                operations: Vec::new(),
                remediation: "Add rollover protection with rate caps or guaranteed renewal terms".to_string(),
            });
        }

        if self.has_last_block_bid_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Auction accepts bids in final block allowing manipulation".to_string(),
                operations: Vec::new(),
                remediation: "Add bid lockout period before auction close (e.g., final 5 blocks)".to_string(),
            });
        }

        if self.has_partial_fill_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Partial fill prioritization can be gamed for advantageous fills".to_string(),
                operations: Vec::new(),
                remediation: "Implement pro-rata fills or randomized fill ordering".to_string(),
            });
        }

        warnings
    }

    fn has_auction_clearing_manipulation(&self) -> bool {
        // Pattern: auction clearing calculation without Sybil protection
        for i in 0..self.bytecode.len().saturating_sub(55) {
            // Look for sorting/matching logic (typical in auction clearing)
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT (sorting)
                let window = &self.bytecode[i.saturating_sub(45)..i+10.min(self.bytecode.len())];
                
                // Check for bid/offer matching
                let matches_bids_offers = window.windows(20).any(|w| {
                    // Pattern: iterate through bids/offers
                    w.iter().filter(|&&op| op == 0x54).count() >= 3 && // Multiple SLOAD (bids)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) && // Compare
                    w.iter().any(|&op| op == 0x01) // ADD (sum matched volume)
                });
                
                if matches_bids_offers {
                    // Check for bid concentration limit
                    let has_concentration_limit = window.windows(15).any(|w| {
                        // Max % of total from single bidder
                        w.iter().any(|&op| op == 0x04) && // DIV (percentage)
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH max %
                        w.iter().any(|&op| op == 0x11) // GT
                    });
                    
                    // Check for minimum bid count
                    let has_min_bidders = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x54) && // SLOAD (bidder count)
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH min
                        w.iter().any(|&op| op == 0x11) // GT
                    });
                    
                    // Check for unique bidder validation
                    let validates_unique_bidders = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (bidder hash)
                        w.iter().any(|&op| op == 0x54) // SLOAD (check seen before)
                    });
                    
                    if !has_concentration_limit && !has_min_bidders && !validates_unique_bidders {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_term_rollover_vulnerability(&self) -> bool {
        // Pattern: rollover function without rate protection
        let rollover_selector = [0xa4, 0xd6, 0x6d, 0xaf]; // rollover() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == rollover_selector {
                    let window = &self.bytecode[i..i+55.min(self.bytecode.len())];
                    
                    // Check for new loan creation
                    let creates_new_loan = window.contains(&0xf0); // CREATE or similar
                    
                    // Check for rate cap on rollover
                    let has_rate_cap = window.windows(12).any(|w| {
                        // New rate <= old_rate * max_increase
                        w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Old + new rate
                        w.iter().any(|&op| op == 0x02) && // MUL (old * max factor)
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    // Check for guaranteed renewal option
                    let has_renewal_guarantee = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (renewal flag)
                        w.iter().any(|&op| op == 0x54) // SLOAD
                    });
                    
                    if creates_new_loan && !has_rate_cap && !has_renewal_guarantee {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_last_block_bid_manipulation(&self) -> bool {
        // Pattern: submitBid() accepts bids until auction end block
        let submit_bid = [0x5c, 0x19, 0xa9, 0x5c]; // submitBid()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == submit_bid {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for bid storage
                    let stores_bid = window.contains(&0x55); // SSTORE
                    
                    // Check for auction end time check
                    let checks_auction_end = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x42 || op == 0x43) && // TIMESTAMP or NUMBER
                        w.iter().any(|&op| op == 0x54) && // SLOAD (auction end)
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    if checks_auction_end {
                        // Check for lockout period (bid deadline before auction end)
                        let has_lockout_period = window.windows(15).any(|w| {
                            // Pattern: current_time < (auction_end - lockout_period)
                            w.iter().any(|&op| op == 0x54) && // SLOAD (auction end)
                            w.iter().any(|&op| op == 0x03) && // SUB (- lockout)
                            w.iter().any(|&op| op == 0x10) // LT
                        });
                        
                        if stores_bid && !has_lockout_period {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_partial_fill_gaming(&self) -> bool {
        // Pattern: fill allocation without fair ordering
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for fill loop
            if self.bytecode[i] == 0x56 { // JUMP (loop iteration)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for fill allocation
                let allocates_fills = window.windows(15).any(|w| {
                    w.iter().any(|&op| op == 0x54) && // SLOAD (bid/offer)
                    w.iter().any(|&op| op == 0x02) && // MUL (fill amount)
                    w.iter().any(|&op| op == 0x55) // SSTORE (allocate)
                });
                
                if allocates_fills {
                    // Check for pro-rata allocation
                    let uses_pro_rata = window.windows(12).any(|w| {
                        // Each participant gets proportional fill
                        w.iter().any(|&op| op == 0x02) && // MUL (participant * total)
                        w.iter().any(|&op| op == 0x04) // DIV (/ sum)
                    });
                    
                    // Check for randomized ordering
                    let randomizes = window.iter().any(|&op| {
                        op == 0x40 || op == 0x44 // BLOCKHASH or PREVRANDAO
                    });
                    
                    if !uses_pro_rata && !randomizes {
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
    fn test_term_auction_manipulation() {
        let vulnerable_bytecode = vec![
            0x54, 0x54, 0x54, // SLOAD x3 (load bids)
            0x10, // LT (sort/match)
            0x01, // ADD (sum - no concentration limit!)
        ];

        let detector = TermFinanceAuctionLendingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("auction") || w.description.contains("clearing")));
    }

    #[test]
    fn test_last_block_bid_manipulation() {
        let vulnerable_bytecode = vec![
            0x63, 0x5c, 0x19, 0xa9, 0x5c, // submitBid()
            0x42, // TIMESTAMP
            0x54, // SLOAD (auction end)
            0x10, // LT (check - no lockout period!)
            0x55, // SSTORE (accept bid)
        ];

        let detector = TermFinanceAuctionLendingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("final block") || w.description.contains("last block")));
    }
}
