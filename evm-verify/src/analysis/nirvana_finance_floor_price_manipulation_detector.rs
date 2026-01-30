use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Nirvana Finance Floor Price Manipulation Detector
/// 
/// Detects vulnerabilities in algorithmic stablecoin floor price mechanisms
/// where floor price can be manipulated to drain treasury reserves.
/// 
/// **Historical Exploit**: Nirvana Finance ($3.6M, July 2022)
/// **Attack Pattern**:
/// 1. Manipulate floor price oracle through low liquidity
/// 2. Mint tokens at manipulated floor price
/// 3. Immediately redeem at true floor price
/// 4. Drain treasury through arbitrage loop
/// 
/// **Detection Strategy**:
/// - Identifies floor price calculations without manipulation resistance
/// - Detects instant mint/redeem patterns without cooldown
/// - Flags treasury depletion vulnerabilities
/// - Checks for mint cap and rate limiting
pub struct NirvanaFinanceFloorPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl NirvanaFinanceFloorPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_manipulable_floor_price() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Floor price calculation vulnerable to manipulation - Nirvana vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use time-weighted reserves and supply for floor price calculations".to_string(),
            });
        }

        if self.has_instant_mint_redeem_arbitrage() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Instant mint/redeem cycle allows treasury drainage".to_string(),
                operations: Vec::new(),
                remediation: "Add time delay between mint and redeem operations".to_string(),
            });
        }

        if self.has_missing_treasury_protection() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Treasury redemption lacks rate limiting or caps".to_string(),
                operations: Vec::new(),
                remediation: "Implement redemption caps and rate limiting mechanisms".to_string(),
            });
        }

        warnings
    }

    fn has_manipulable_floor_price(&self) -> bool {
        // Pattern: floor price based on instant reserves/supply ratio
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x31 { // BALANCE (treasury reserves)
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Check for division by totalSupply
                let has_supply_div = window.iter().any(|&op| {
                    op == 0x18 // TOTALSSUPPLY
                }) && window.contains(&0x04); // DIV
                
                // Check for TWAP or time-weighting
                let has_twap = window.iter().any(|&op| {
                    op == 0x42 || op == 0x54 // TIMESTAMP or SLOAD (stored prices)
                });
                
                if has_supply_div && !has_twap {
                    return true;
                }
            }
        }
        false
    }

    fn has_instant_mint_redeem_arbitrage(&self) -> bool {
        // Pattern: mint() followed by redeem() in same transaction
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19]; // mint()
        let redeem_selector = [0xdb, 0x00, 0x6a, 0x75]; // redeem()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_selector {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Look for redeem in same execution path
                    let has_redeem = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == redeem_selector
                    });
                    
                    // Check for time delay between operations
                    let has_delay = window.iter().any(|&op| {
                        op == 0x42 // TIMESTAMP check
                    });
                    
                    if has_redeem && !has_delay {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_treasury_protection(&self) -> bool {
        // Pattern: redeem() without rate limiting
        let redeem_selector = [0xdb, 0x00, 0x6a, 0x75];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == redeem_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for redemption cap
                    let has_cap = window.iter().any(|&op| {
                        op == 0x10 || op == 0x11 // LT or GT (cap check)
                    });
                    
                    // Check for rate limiting
                    let has_rate_limit = window.iter().any(|&op| {
                        op == 0x42 // TIMESTAMP (rate tracking)
                    });
                    
                    if !has_cap && !has_rate_limit {
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
    fn test_nirvana_floor_price_manipulation() {
        let vulnerable_bytecode = vec![
            0x31, // BALANCE (reserves)
            0x18, // TOTALSSUPPLY
            0x04, // DIV (floor price, no TWAP!)
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint()
            0x63, 0xdb, 0x00, 0x6a, 0x75, // redeem() (instant!)
        ];

        let detector = NirvanaFinanceFloorPriceManipulationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
