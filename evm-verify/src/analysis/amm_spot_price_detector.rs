/// AMM Spot Price Manipulation Detector
/// Detects vulnerabilities where contracts use AMM spot prices instead of TWAP,
/// allowing price manipulation via flash loans
///
/// Famous exploits: Mango Markets ($110M), Avi Eisenberg attacks, Cream Finance

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AMMSpotPriceVulnerability {
    pub vulnerability_type: AMMPriceIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AMMPriceIssueType {
    SpotPriceInsteadOfTWAP,        // Using current price instead of time-weighted
    SingleBlockPriceOracle,         // Price from one block only
    UnprotectedReserveRatio,        // getReserves() used for pricing
    FlashLoanPriceManipulation,     // Price can be manipulated in same tx
    MissingPriceValidation,         // No sanity checks on price
}

pub struct AMMSpotPriceDetector {
    bytecode: Vec<u8>,
}

impl AMMSpotPriceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AMMSpotPriceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Uniswap V2 getReserves() for pricing
        vulnerabilities.extend(self.detect_get_reserves_pricing());

        // Pattern 2: Single-block price reads
        vulnerabilities.extend(self.detect_single_block_price());

        // Pattern 3: Missing TWAP implementation
        vulnerabilities.extend(self.detect_missing_twap());

        vulnerabilities
    }

    /// Detect: Using getReserves() for price calculations
    fn detect_get_reserves_pricing(&self) -> Vec<AMMSpotPriceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for getReserves selector: 0x0902f1ac
            if self.is_get_reserves_call(pc) {
                // Check if result is used in division (price calculation)
                if self.has_price_calculation_after(pc, 100) {
                    let has_twap_check = self.has_twap_pattern_nearby(pc);
                    
                    if !has_twap_check {
                        vulnerabilities.push(AMMSpotPriceVulnerability {
                            vulnerability_type: AMMPriceIssueType::SpotPriceInsteadOfTWAP,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.90,
                            description: format!(
                                "Contract calls getReserves() at PC {} and uses result for \
                                pricing without TWAP. Vulnerable to flash loan price manipulation.",
                                pc
                            ),
                            exploit_scenario:
                                "Flash Loan Price Manipulation (Mango-style):\n\
                                 1. Attacker takes flash loan of 1M tokens\n\
                                 2. Swaps through AMM, moving price 50%\n\
                                 3. Victim contract reads getReserves() → manipulated price\n\
                                 4. Victim executes at bad price (liquidation, mint, etc.)\n\
                                 5. Attacker reverses swap, repays loan, profits\n\n\
                                 Real Impact: $100M+ stolen across DeFi\n\
                                 Fix: Use Uniswap V2 TWAP or Chainlink oracles".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Price read from single block
    fn detect_single_block_price(&self) -> Vec<AMMSpotPriceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for AMM price query
            if self.is_amm_price_query(pc) {
                // Check if there's timestamp/block accumulator logic (TWAP)
                let has_accumulator = self.has_accumulator_pattern(pc);
                let has_multiple_reads = self.has_multiple_price_reads(pc, 200);
                
                if !has_accumulator && !has_multiple_reads {
                    vulnerabilities.push(AMMSpotPriceVulnerability {
                        vulnerability_type: AMMPriceIssueType::SingleBlockPriceOracle,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Price read at PC {} from single block. No time-weighted average. \
                            Manipulable within single transaction.",
                            pc
                        ),
                        exploit_scenario:
                            "Single-Block Attack:\n\
                             1. Manipulate AMM price in transaction start\n\
                             2. Contract reads manipulated price\n\
                             3. Execute profitable action at bad price\n\
                             4. Restore price before tx ends\n\
                             5. All in one atomic transaction\n\n\
                             Defense: Multi-block TWAP cannot be manipulated atomically".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: No TWAP implementation when using AMM prices
    fn detect_missing_twap(&self) -> Vec<AMMSpotPriceVulnerability> {
        let mut vulnerabilities = Vec::new();

        let uses_amm = self.has_amm_interaction();
        let has_twap = self.has_twap_implementation();
        let has_oracle = self.has_oracle_integration();

        if uses_amm && !has_twap && !has_oracle {
            vulnerabilities.push(AMMSpotPriceVulnerability {
                vulnerability_type: AMMPriceIssueType::FlashLoanPriceManipulation,
                severity: SecuritySeverity::High,
                confidence: 0.70,
                description:
                    "Contract interacts with AMM but doesn't implement TWAP or use external oracle. \
                    Likely vulnerable to flash loan price manipulation.".to_string(),
                exploit_scenario:
                    "Comprehensive Flash Loan Attack:\n\
                     1. Borrow massive amount via Aave/dYdX flash loan\n\
                     2. Manipulate AMM reserves through large swap\n\
                     3. Target contract reads spot price\n\
                     4. Execute exploit (liquidate, mint, arb, etc.)\n\
                     5. Reverse manipulation\n\
                     6. Repay flash loan with profit\n\n\
                     Mitigation Options:\n\
                     - Uniswap V2/V3 TWAP (consult() function)\n\
                     - Chainlink Price Feeds\n\
                     - Multi-source price aggregation\n\
                     - Minimum liquidity requirements".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    // Helper methods

    fn is_get_reserves_call(&self, pc: usize) -> bool {
        if pc + 4 >= self.bytecode.len() {
            return false;
        }
        
        // getReserves selector: 0x0902f1ac
        self.bytecode[pc..pc+4].windows(4).any(|w| {
            w == [0x09, 0x02, 0xf1, 0xac]
        })
    }

    fn has_price_calculation_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        // Look for division (reserve0 / reserve1 = price)
        self.bytecode[pc..end].contains(&0x04) // DIV
    }

    fn has_twap_pattern_nearby(&self, pc: usize) -> bool {
        let start = pc.saturating_sub(100);
        let end = (pc + 100).min(self.bytecode.len());
        
        // TWAP requires:
        // 1. Multiple price observations
        // 2. Timestamp tracking (TIMESTAMP opcode: 0x42)
        // 3. Accumulator (ADD with timestamps)
        
        let has_timestamp = self.bytecode[start..end].contains(&0x42);
        let has_accumulator = self.bytecode[start..end]
            .windows(2)
            .any(|w| w[0] == 0x42 && w[1] == 0x01); // TIMESTAMP, ADD
        
        has_timestamp && has_accumulator
    }

    fn is_amm_price_query(&self, pc: usize) -> bool {
        // Common AMM selectors:
        // - getReserves(): 0x0902f1ac
        // - slot0() (Uni V3): 0x3850c7bd
        // - getAmountOut(): 0x054d50d4
        
        if pc + 4 >= self.bytecode.len() {
            return false;
        }
        
        self.bytecode[pc..pc+4].windows(4).any(|w| {
            w == [0x09, 0x02, 0xf1, 0xac] || // getReserves
            w == [0x38, 0x50, 0xc7, 0xbd] || // slot0
            w == [0x05, 0x4d, 0x50, 0xd4]    // getAmountOut
        })
    }

    fn has_accumulator_pattern(&self, pc: usize) -> bool {
        let start = pc.saturating_sub(50);
        let end = (pc + 50).min(self.bytecode.len());
        
        // Accumulator pattern: SLOAD, ADD, SSTORE
        for i in start..end.saturating_sub(4) {
            if self.bytecode[i] == 0x54 && // SLOAD
               self.bytecode[i + 1] == 0x01 && // ADD
               self.bytecode.get(i + 3) == Some(&0x55) { // SSTORE
                return true;
            }
        }
        false
    }

    fn has_multiple_price_reads(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        // Count price queries
        let mut count = 0;
        for i in pc..end {
            if self.is_amm_price_query(i) {
                count += 1;
            }
        }
        
        count >= 2
    }

    fn has_amm_interaction(&self) -> bool {
        // Check for common AMM interactions
        self.bytecode.windows(4).any(|w| {
            w == [0x09, 0x02, 0xf1, 0xac] || // getReserves (Uni V2)
            w == [0x38, 0x50, 0xc7, 0xbd] || // slot0 (Uni V3)
            w == [0x02, 0x2c, 0x0d, 0x9f]    // swap (Uni V2)
        })
    }

    fn has_twap_implementation(&self) -> bool {
        // TWAP requires timestamp accumulation
        let has_timestamp = self.bytecode.contains(&0x42); // TIMESTAMP
        
        // Look for observation pattern (price * timeElapsed)
        let has_time_weighted = self.bytecode.windows(3).any(|w| {
            w[0] == 0x42 && w[1] == 0x02 // TIMESTAMP, MUL
        });
        
        has_timestamp && has_time_weighted
    }

    fn has_oracle_integration(&self) -> bool {
        // Chainlink selectors:
        // - latestRoundData(): 0xfeaf968c
        // - latestAnswer(): 0x50d25bcd
        
        self.bytecode.windows(4).any(|w| {
            w == [0xfe, 0xaf, 0x96, 0x8c] || // latestRoundData
            w == [0x50, 0xd2, 0x5b, 0xcd]    // latestAnswer
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_reserves_without_twap() {
        let bytecode = vec![
            0x09, 0x02, 0xf1, 0xac, // getReserves selector
            0xFA, // STATICCALL
            0x04, // DIV (price calculation)
            // No TIMESTAMP (0x42) = no TWAP
        ];
        
        let detector = AMMSpotPriceDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect spot price usage");
    }
}
