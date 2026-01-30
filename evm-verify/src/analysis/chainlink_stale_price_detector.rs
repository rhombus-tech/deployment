use serde::{Deserialize, Serialize};

/// Chainlink Stale Price Detector
/// 
/// Detects when Chainlink oracle prices are not checked for staleness.
/// CRITICAL: Multiple major exploits from using stale price data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainlinkStalePriceVulnerability {
    /// Critical: No timestamp check on price feed
    NoTimestampCheck {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: No heartbeat validation
    NoHeartbeatValidation {
        description: String,
        location: usize,
    },
    /// High: No round completeness check
    NoRoundCompletenessCheck {
        description: String,
        location: usize,
    },
    /// Medium: updatedAt not compared to threshold
    UpdatedAtNotValidated {
        description: String,
        location: usize,
    },
}

pub struct ChainlinkStalePriceDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkStalePriceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ChainlinkStalePriceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect latestRoundData() calls without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_latest_round_data_call(i) {
                if !self.validates_updated_at(i, i + 150) {
                    vulnerabilities.push(ChainlinkStalePriceVulnerability::NoTimestampCheck {
                        description: "latestRoundData() called without validating updatedAt timestamp - stale price risk".to_string(),
                        location: i,
                        confidence: 0.95,
                    });
                }
                
                if !self.checks_round_completeness(i, i + 150) {
                    vulnerabilities.push(ChainlinkStalePriceVulnerability::NoRoundCompletenessCheck {
                        description: "Price feed answeredInRound not checked against roundId - incomplete round risk".to_string(),
                        location: i,
                    });
                }
                
                if !self.validates_heartbeat(i, i + 150) {
                    vulnerabilities.push(ChainlinkStalePriceVulnerability::NoHeartbeatValidation {
                        description: "No heartbeat interval validation - feed may be stale beyond acceptable threshold".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_latest_round_data_call(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // latestRoundData() selector: 0xfeaf968c
        self.bytecode[location..location + 30]
            .windows(4)
            .any(|w| w == [0xfe, 0xaf, 0x96, 0x8c])
    }
    
    fn validates_updated_at(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // After latestRoundData(), must validate updatedAt (4th return value)
        // Pattern: Extract updatedAt, compare with TIMESTAMP or threshold
        
        let mut has_timestamp_comparison = false;
        let mut found_sub = false;
        let mut found_comparison = false;
        
        for i in start..range_end {
            // TIMESTAMP opcode for current time
            if self.bytecode[i] == 0x42 {
                has_timestamp_comparison = true;
            }
            
            // SUB (current_time - updatedAt)
            if has_timestamp_comparison && self.bytecode[i] == 0x03 {
                found_sub = true;
            }
            
            // LT/GT comparison (age check)
            if found_sub && (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) {
                found_comparison = true;
            }
            
            // Must have REVERT if stale
            if found_comparison && self.bytecode[i] == 0xFD {
                return true;
            }
        }
        
        false
    }
    
    fn checks_round_completeness(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // answeredInRound >= roundId check
        // Pattern: Compare two values with GT/LT and revert if incomplete
        
        let comparison_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x10 || b == 0x11) // LT or GT
            .count();
        
        // Need at least 2 comparisons (updatedAt + answeredInRound)
        comparison_count >= 2
    }
    
    fn validates_heartbeat(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Heartbeat validation: updatedAt + HEARTBEAT > block.timestamp
        // Look for addition followed by comparison
        
        let mut has_add = false;
        let mut has_timestamp = false;
        
        for i in start..range_end.saturating_sub(5) {
            if self.bytecode[i] == 0x01 { // ADD
                has_add = true;
            }
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                has_timestamp = true;
            }
            
            // If both present with comparison, heartbeat check exists
            if has_add && has_timestamp {
                for j in i..i.saturating_add(10).min(range_end) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
}
