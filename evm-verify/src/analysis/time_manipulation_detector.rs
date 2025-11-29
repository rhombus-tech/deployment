// Time Manipulation Attack Detector
// Detects vulnerabilities where miners can manipulate block.timestamp for profit

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeManipulationVulnerability {
    pub vulnerability_type: TimeManipulationType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub manipulation_window: u64, // seconds
    pub economic_impact: EconomicImpact,
    pub affected_functions: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeManipulationType {
    CliffVesting,           // Vesting unlocks at exact timestamp
    AuctionManipulation,    // Auction end time can be gamed
    RandomnessFromTime,     // Using timestamp for randomness
    PriceOracleStale,       // Price valid for X seconds
    DeadlineBypass,         // Deadline can be manipulated
    TimeBasedAccess,        // Access control based on time
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicImpact {
    pub value_at_risk: u128,
    pub manipulation_cost: u128, // Cost to manipulate (miner tip)
    pub is_profitable: bool,
}

pub struct TimeManipulationDetector {
    bytecode: Vec<u8>,
}

impl TimeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze(&self) -> Vec<TimeManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for different time manipulation patterns
        vulnerabilities.extend(self.detect_cliff_vesting());
        vulnerabilities.extend(self.detect_auction_manipulation());
        vulnerabilities.extend(self.detect_randomness_from_time());
        vulnerabilities.extend(self.detect_stale_oracle_price());
        vulnerabilities.extend(self.detect_deadline_bypass());

        vulnerabilities
    }

    /// Detect cliff vesting that can be manipulated
    fn detect_cliff_vesting(&self) -> Vec<TimeManipulationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: TIMESTAMP > storage_value (cliff check)
        // Followed by high-value transfer
        
        // Look for: TIMESTAMP, SLOAD, GT, JUMPI pattern
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                // Check if followed by comparison
                if self.is_timestamp_comparison(&self.bytecode[i..i+10]) {
                    // Check if this guards a high-value operation
                    if self.has_value_transfer_after(i) {
                        vulns.push(TimeManipulationVulnerability {
                            vulnerability_type: TimeManipulationType::CliffVesting,
                            severity: SecuritySeverity::High,
                            description: "Vesting cliff uses block.timestamp which miners can manipulate ±15 seconds".to_string(),
                            manipulation_window: 15,
                            economic_impact: EconomicImpact {
                                value_at_risk: 1_000_000_000_000_000_000_000u128, // Estimate $1M
                                manipulation_cost: 10_000_000_000_000_000u128,     // ~$10K miner tip
                                is_profitable: true,
                            },
                            affected_functions: vec!["claim".to_string(), "unlock".to_string()],
                            remediation: "Use block.number instead of block.timestamp for time-based logic, or add safety margin".to_string(),
                        });
                    }
                }
            }
        }

        vulns
    }

    /// Detect auction manipulation via timestamp
    fn detect_auction_manipulation(&self) -> Vec<TimeManipulationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Auction ends at exact timestamp
        // TIMESTAMP, SLOAD(endTime), GT, JUMPI
        // Miners can delay block to win auction

        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                // Check for auction-like pattern
                if self.is_auction_pattern(&self.bytecode[i..i+15]) {
                    vulns.push(TimeManipulationVulnerability {
                        vulnerability_type: TimeManipulationType::AuctionManipulation,
                        severity: SecuritySeverity::Critical,
                        description: "Auction end time based on block.timestamp - miner with winning bid can delay block".to_string(),
                        manipulation_window: 15,
                        economic_impact: EconomicImpact {
                            value_at_risk: 10_000_000_000_000_000_000_000u128, // $10M NFT
                            manipulation_cost: 50_000_000_000_000_000u128,      // $50K to delay
                            is_profitable: true,
                        },
                        affected_functions: vec!["endAuction".to_string(), "finalize".to_string()],
                        remediation: "Use commit-reveal scheme or block.number for auction timing".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detect randomness derived from timestamp
    fn detect_randomness_from_time(&self) -> Vec<TimeManipulationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: TIMESTAMP used in MOD operation (generating random number)
        // TIMESTAMP, PUSH, MOD -> predictable randomness

        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                // Check if used in modulo operation (randomness)
                if i + 3 < self.bytecode.len() && self.bytecode[i + 2] == 0x06 {  // MOD
                    vulns.push(TimeManipulationVulnerability {
                        vulnerability_type: TimeManipulationType::RandomnessFromTime,
                        severity: SecuritySeverity::Critical,
                        description: "Randomness derived from block.timestamp - completely predictable by miners".to_string(),
                        manipulation_window: 15,
                        economic_impact: EconomicImpact {
                            value_at_risk: 5_000_000_000_000_000_000_000u128,
                            manipulation_cost: 100_000_000_000_000_000u128,
                            is_profitable: true,
                        },
                        affected_functions: vec!["lottery".to_string(), "random".to_string()],
                        remediation: "Use Chainlink VRF or commit-reveal scheme for randomness".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detect stale oracle prices based on timestamp
    fn detect_stale_oracle_price(&self) -> Vec<TimeManipulationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Check if price update is within X seconds
        // If X is large, miner can use stale price

        // Look for: TIMESTAMP - lastUpdate < threshold pattern
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                if self.is_staleness_check(&self.bytecode[i..i+20]) {
                    // Check if threshold is > 60 seconds (manipulatable)
                    let threshold = self.extract_staleness_threshold(&self.bytecode[i..i+20]);
                    if threshold > 60 {
                        vulns.push(TimeManipulationVulnerability {
                            vulnerability_type: TimeManipulationType::PriceOracleStale,
                            severity: SecuritySeverity::High,
                            description: format!("Oracle price valid for {} seconds - miner can delay block to use stale price", threshold),
                            manipulation_window: threshold,
                            economic_impact: EconomicImpact {
                                value_at_risk: 2_000_000_000_000_000_000_000u128,
                                manipulation_cost: 20_000_000_000_000_000u128,
                                is_profitable: true,
                            },
                            affected_functions: vec!["getPrice".to_string(), "updatePrice".to_string()],
                            remediation: "Reduce staleness threshold to < 60 seconds or use block.number".to_string(),
                        });
                    }
                }
            }
        }

        vulns
    }

    /// Detect deadline bypass via timestamp manipulation
    fn detect_deadline_bypass(&self) -> Vec<TimeManipulationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: require(block.timestamp < deadline)
        // Miner can manipulate to bypass deadline

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                if self.is_deadline_check(&self.bytecode[i..i+10]) {
                    vulns.push(TimeManipulationVulnerability {
                        vulnerability_type: TimeManipulationType::DeadlineBypass,
                        severity: SecuritySeverity::Medium,
                        description: "Deadline enforced with block.timestamp can be bypassed by ±15 seconds".to_string(),
                        manipulation_window: 15,
                        economic_impact: EconomicImpact {
                            value_at_risk: 500_000_000_000_000_000_000u128,
                            manipulation_cost: 5_000_000_000_000_000u128,
                            is_profitable: true,
                        },
                        affected_functions: vec!["swap".to_string(), "execute".to_string()],
                        remediation: "Add buffer to deadline or use block.number for strict timing".to_string(),
                    });
                }
            }
        }

        vulns
    }

    // === HELPER METHODS ===

    fn is_timestamp_comparison(&self, bytecode: &[u8]) -> bool {
        // Check for TIMESTAMP, SLOAD, GT/LT pattern
        bytecode.len() >= 5 && 
        bytecode[0] == 0x42 &&  // TIMESTAMP
        (bytecode[2] == 0x54 || bytecode[2] == 0x55) && // SLOAD
        (bytecode[4] == 0x11 || bytecode[4] == 0x10)    // GT or LT
    }

    fn has_value_transfer_after(&self, offset: usize) -> bool {
        // Check if CALL with value appears within next 50 bytes
        for i in offset..offset.saturating_add(50).min(self.bytecode.len()) {
            if i < self.bytecode.len() && self.bytecode[i] == 0xF1 {  // CALL
                return true;
            }
        }
        false
    }

    fn is_auction_pattern(&self, bytecode: &[u8]) -> bool {
        // Look for auction-specific pattern
        // TIMESTAMP, SLOAD(endTime), GT, JUMPI, CALL (finalize payment)
        bytecode.len() >= 10 &&
        bytecode[0] == 0x42 &&  // TIMESTAMP
        bytecode[2] == 0x54 &&  // SLOAD
        bytecode[4] == 0x11 &&  // GT
        bytecode[5] == 0x57     // JUMPI
    }

    fn is_staleness_check(&self, bytecode: &[u8]) -> bool {
        // TIMESTAMP, SLOAD, SUB, PUSH(threshold), LT
        bytecode.len() >= 8 &&
        bytecode[0] == 0x42 &&  // TIMESTAMP
        bytecode[2] == 0x54 &&  // SLOAD
        bytecode[3] == 0x03 &&  // SUB
        bytecode[5] == 0x10     // LT
    }

    fn extract_staleness_threshold(&self, bytecode: &[u8]) -> u64 {
        // Try to extract the threshold value from bytecode
        // This is a simplified version
        if bytecode.len() >= 6 && bytecode[4] == 0x60 {  // PUSH1
            return bytecode[5] as u64;
        }
        300 // Default assumption: 5 minutes
    }

    fn is_deadline_check(&self, bytecode: &[u8]) -> bool {
        // TIMESTAMP, SLOAD(deadline), LT
        bytecode.len() >= 5 &&
        bytecode[0] == 0x42 &&  // TIMESTAMP
        bytecode[2] == 0x54 &&  // SLOAD
        bytecode[4] == 0x10     // LT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cliff_vesting() {
        // Bytecode with TIMESTAMP comparison
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD
            0x11, // GT
            0x60, 0x10, // PUSH1 16
            0x57, // JUMPI
            0xF1, // CALL (value transfer)
        ];
        
        let detector = TimeManipulationDetector::new(bytecode);
        let vulns = detector.detect_cliff_vesting();
        
        assert!(vulns.len() > 0, "Should detect cliff vesting vulnerability");
    }

    #[test]
    fn test_detect_randomness_from_time() {
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x60, 0x64, // PUSH1 100
            0x06, // MOD (generating random 0-99)
        ];
        
        let detector = TimeManipulationDetector::new(bytecode);
        let vulns = detector.detect_randomness_from_time();
        
        assert!(vulns.len() > 0, "Should detect timestamp randomness");
    }
}
