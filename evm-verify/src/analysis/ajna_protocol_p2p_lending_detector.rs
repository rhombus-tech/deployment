use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Ajna Protocol Peer-to-Peer Lending Detector
/// 
/// Detects vulnerabilities in Ajna's permissionless P2P lending pools where borrowers
/// and lenders interact directly through bucket-based liquidity and Dutch auction liquidations.
/// 
/// **Ajna Context**:
/// Ajna is a non-custodial, peer-to-peer lending protocol with:
/// - Bucket-based liquidity provision (lenders choose price buckets)
/// - Dutch auction liquidations (descending price)
/// - No governance, oracles, or external price feeds
/// - Permissionless pool creation
/// 
/// **Attack Patterns**:
/// 1. Bucket manipulation - gaming liquidity distribution across buckets
/// 2. Dutch auction frontrunning - sniping liquidations at optimal price
/// 3. Pool collateralization gaming - manipulating pool health
/// 4. Interest rate manipulation via utilization
/// 5. Liquidation avoidance via bucket shifting
/// 
/// **Detection Strategy**:
/// - Identifies bucket operations without manipulation protection
/// - Detects Dutch auction timing exploits
/// - Flags pool health calculations without safeguards
/// - Checks for interest accrual gaming
/// - Validates liquidation mechanism integrity
pub struct AjnaProtocolP2pLendingDetector {
    bytecode: Vec<u8>,
}

impl AjnaProtocolP2pLendingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_bucket_manipulation_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Ajna bucket liquidity manipulation - lenders can game bucket positioning".to_string(),
                operations: Vec::new(),
                remediation: "Add bucket movement restrictions and time delays between bucket operations".to_string(),
            });
        }

        if self.has_dutch_auction_frontrunning() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Dutch auction liquidation vulnerable to frontrunning at optimal price".to_string(),
                operations: Vec::new(),
                remediation: "Add MEV protection or randomized auction timing to prevent sniping".to_string(),
            });
        }

        if self.has_pool_collateralization_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Pool collateralization ratio can be manipulated via coordinated actions".to_string(),
                operations: Vec::new(),
                remediation: "Implement TWAP-style collateral tracking and manipulation detection".to_string(),
            });
        }

        if self.has_interest_rate_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Interest rates manipulable via utilization gaming".to_string(),
                operations: Vec::new(),
                remediation: "Add interest rate smoothing and utilization bounds".to_string(),
            });
        }

        warnings
    }

    fn has_bucket_manipulation_vulnerability(&self) -> bool {
        // Pattern: addQuoteToken() or moveQuoteToken() without protection
        let add_quote = [0x1a, 0x9c, 0xf3, 0x02]; // addQuoteToken()
        let move_quote = [0x6f, 0x9f, 0xb9, 0x8a]; // moveQuoteToken()
        
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == add_quote || selector == move_quote {
                    let window = &self.bytecode[i..i+55.min(self.bytecode.len())];
                    
                    // Check for bucket index update
                    let updates_bucket = window.contains(&0x55); // SSTORE
                    
                    // Check for bucket movement time delay
                    let has_time_delay = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) && // SLOAD (last move time)
                        w.iter().any(|&op| op == 0x01) && // ADD (+ delay)
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    // Check for bucket movement limits
                    let has_movement_limit = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x54) && // SLOAD (movement count)
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH max
                        w.iter().any(|&op| op == 0x11) // GT
                    });
                    
                    // Check for bucket concentration limits
                    let has_concentration_limit = window.windows(15).any(|w| {
                        // Prevent too much liquidity in single bucket
                        w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Load bucket amounts
                        w.iter().any(|&op| op == 0x04) && // DIV (percentage)
                        w.iter().any(|&op| op == 0x11) // GT (check concentration)
                    });
                    
                    if updates_bucket && !has_time_delay && !has_movement_limit && !has_concentration_limit {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_dutch_auction_frontrunning(&self) -> bool {
        // Pattern: take() or liquidation function without MEV protection
        let take_selector = [0xb2, 0xe3, 0xce, 0xba]; // take()
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == take_selector {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check for descending price calculation
                    let calculates_dutch_price = window.windows(15).any(|w| {
                        // Pattern: starting_price - (time_elapsed * decay_rate)
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x03) && // SUB (price decay)
                        w.iter().any(|&op| op == 0x02) // MUL (time * rate)
                    });
                    
                    if calculates_dutch_price {
                        // Check for MEV protection (commit-reveal, randomness)
                        let has_mev_protection = window.windows(12).any(|w| {
                            w.iter().any(|&op| op == 0x20) && // KECCAK256 (commit)
                            w.iter().any(|&op| op == 0x54) // SLOAD (reveal)
                        });
                        
                        // Check for minimum time in auction
                        let has_min_time = window.windows(10).any(|w| {
                            w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                            w.iter().any(|&op| op == 0x01) && // ADD (start + min)
                            w.iter().any(|&op| op == 0x10) // LT
                        });
                        
                        // Check for price randomization
                        let has_randomness = window.iter().any(|&op| {
                            op == 0x40 || op == 0x44 // BLOCKHASH or PREVRANDAO
                        });
                        
                        if !has_mev_protection && !has_min_time && !has_randomness {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_pool_collateralization_gaming(&self) -> bool {
        // Pattern: collateralization ratio calculation without manipulation protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x04 { // DIV (collateral / debt)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for collateralization ratio calculation
                let calculates_ratio = window.windows(15).any(|w| {
                    // Pattern: total_collateral / total_debt
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Load collateral + debt
                    w.iter().any(|&op| op == 0x04) // DIV
                });
                
                if calculates_ratio {
                    // Check for TWAP-style smoothing
                    let has_smoothing = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().filter(|&&op| op == 0x54).count() >= 3 // Historical values
                    });
                    
                    // Check for manipulation detection
                    let detects_manipulation = window.windows(15).any(|w| {
                        // Check if ratio changed too quickly
                        w.iter().any(|&op| op == 0x03) && // SUB (new - old)
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH max change
                        w.iter().any(|&op| op == 0x11) // GT
                    });
                    
                    if !has_smoothing && !detects_manipulation {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_interest_rate_manipulation(&self) -> bool {
        // Pattern: interest rate calculation based on utilization without bounds
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x04 { // DIV (borrowed / supplied = utilization)
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for utilization-based interest
                let calculates_interest_from_util = window.windows(15).any(|w| {
                    // Pattern: utilization * interest_multiplier
                    w.iter().any(|&op| op == 0x04) && // DIV (utilization)
                    w.iter().any(|&op| op == 0x02) // MUL (interest rate)
                });
                
                if calculates_interest_from_util {
                    // Check for interest rate bounds
                    let has_rate_bounds = window.windows(12).any(|w| {
                        w.iter().filter(|&&op| op >= 0x60 && op <= 0x7f).count() >= 2 && // Min/max rate
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    // Check for rate change limits
                    let has_change_limit = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x03) && // SUB (rate delta)
                        w.iter().any(|&op| op == 0x11) // GT (check max change)
                    });
                    
                    if !has_rate_bounds && !has_change_limit {
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
    fn test_ajna_bucket_manipulation() {
        let vulnerable_bytecode = vec![
            0x63, 0x1a, 0x9c, 0xf3, 0x02, // addQuoteToken()
            0x55, // SSTORE (bucket update - no time delay!)
        ];

        let detector = AjnaProtocolP2pLendingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("Ajna") || w.description.contains("bucket")));
    }

    #[test]
    fn test_dutch_auction_frontrunning() {
        let vulnerable_bytecode = vec![
            0x63, 0xb2, 0xe3, 0xce, 0xba, // take()
            0x42, // TIMESTAMP
            0x03, // SUB (price decay)
            0x02, // MUL (calculate price - no MEV protection!)
        ];

        let detector = AjnaProtocolP2pLendingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("Dutch auction") || w.description.contains("frontrunning")));
    }
}
